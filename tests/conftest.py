"""
Shared fixtures for the auro-runtime test suite.

Design notes for anyone adding tests:

* The tool registry is populated by importing `runtime_tools` for its side
  effects. The `registry` fixture does that for you — never import
  `runtime_tools` at module scope in a test file and assume ordering.
* Tests must not leave files behind in the repo. Use `temp_output_file` for
  anything that writes through the real file tools; it cleans up both the file
  and any `.auro_archive/` backup.
* `_WRITABLE_DIRS` and friends in `runtime_tools.file_tools` are computed at
  import time from env vars, so monkeypatching the env inside a test does not
  change them. Write into `output/` (already allowlisted) instead.
* Audit events are captured with `audit_events`, which installs a collector for
  the duration of the test. Without it, events go to `auro_audit.jsonl` in the
  repo root and pollute the working tree.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# --- Paths -----------------------------------------------------------------


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Absolute path to the repository root."""
    return REPO_ROOT


# --- Registries ------------------------------------------------------------


@pytest.fixture(scope="session")
def registry() -> dict:
    """The populated tool registry: name -> (callable, doc, args_schema)."""
    import runtime_tools  # noqa: F401 — side-effect import registers every tool
    from auro_runtime.executor import get_registry

    return get_registry()


@pytest.fixture(scope="session")
def guard_registry() -> dict:
    """The guard registry: guard name -> guard callable."""
    from auro_runtime.guards import get_guard_registry

    return get_guard_registry()


@pytest.fixture(scope="session")
def policies(repo_root: Path) -> list:
    """All PolicyBinding objects loaded from the repo's policies/ directory."""
    from auro_runtime.policy import load_policies

    return load_policies(str(repo_root / "policies"))


@pytest.fixture(scope="session")
def policy_rules(policies: list) -> list:
    """Every PolicyRule across all bindings, flattened."""
    return [rule for binding in policies for rule in binding.rules]


@pytest.fixture(scope="session")
def enforceable_rules(policy_rules: list) -> list:
    """Only the rules that actually bind a guard (the ones the executor acts on)."""
    return [r for r in policy_rules if r.guard]


# --- Builders --------------------------------------------------------------


@pytest.fixture
def make_tool_call():
    """Build a ToolCallOutput. make_tool_call("echo", {"message": "hi"})"""
    from auro_runtime.schemas import ToolCallOutput

    def _make(tool: str, args: dict | None = None, reason: str = "test call"):
        return ToolCallOutput(tool=tool, args=args or {}, reason=reason)

    return _make


@pytest.fixture
def make_rule():
    """
    Build a PolicyRule for guard/enforcement tests.

    make_rule(guard="check_destructive_action", enforcement="block",
              tools=["delete_file"])
    """
    from auro_runtime.schemas import PolicyRule

    def _make(
        guard: str | None = None,
        enforcement: str = "block",
        on_error: str = "fail_closed",
        tools: list[str] | None = None,
        directives: list[str] | None = None,
        rule_id: str = "test_rule",
        description: str = "Test rule.",
    ):
        return PolicyRule(
            id=rule_id,
            description=description,
            guard=guard,
            enforcement=enforcement,
            on_error=on_error,
            tools=tools,
            directives=directives,
        )

    return _make


@pytest.fixture
def make_guard_context():
    """Build a GuardContext directly, for unit-testing individual guards."""
    from auro_runtime.guards import GuardContext

    def _make(
        tool_name: str,
        args: dict | None = None,
        raw_args: dict | None = None,
        reason: str = "test",
        directive_id: str | None = None,
        run_history: list[dict] | None = None,
    ):
        resolved = args or {}
        return GuardContext(
            tool_name=tool_name,
            raw_args=raw_args if raw_args is not None else resolved,
            args=resolved,
            reason=reason,
            directive_id=directive_id,
            run_history=run_history or [],
        )

    return _make


# --- Audit -----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_audit_log(tmp_path, monkeypatch):
    """
    Point the audit log at a temp file for EVERY test.

    Any test that exercises execute() or the file tools emits audit events. Without
    this, tests that don't happen to use the `audit_events` fixture write them into
    auro_audit.jsonl in the repo root. `audit_events` still takes precedence when a
    test wants to inspect events, since write_audit_event checks the collector first.
    """
    monkeypatch.setenv("AURO_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


@pytest.fixture
def audit_events():
    """
    Capture audit events emitted during the test instead of writing them to
    auro_audit.jsonl. Yields the live list — assert against it after the call.
    """
    from auro_runtime.audit import set_audit_collector

    collected: list[dict] = []
    set_audit_collector(collected)
    try:
        yield collected
    finally:
        set_audit_collector(None)


# --- Filesystem ------------------------------------------------------------


@pytest.fixture
def temp_output_file(repo_root: Path):
    """
    Register repo-relative paths for cleanup after the test, including any
    .auro_archive/ backup the write/delete tools may have created.

        def test_x(temp_output_file):
            path = temp_output_file("output/probe.txt")
            write_file(path, "data")
    """
    registered: list[str] = []

    def _register(rel_path: str) -> str:
        registered.append(rel_path)
        return rel_path

    yield _register

    archive = repo_root / ".auro_archive"
    for rel in registered:
        target = repo_root / rel
        if target.exists():
            target.unlink()
        if archive.is_dir():
            stem = Path(rel).name
            for leftover in archive.glob(f"*{stem}*"):
                if leftover.is_file():
                    leftover.unlink()


# --- Stub model backend ----------------------------------------------------


class _StubHandler(BaseHTTPRequestHandler):
    """Serves scripted /v1/chat/completions responses. Set by _StubServer."""

    script: list = []
    received: list = []

    def log_message(self, *args):
        pass  # keep pytest output clean

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        type(self).received.append(body)
        idx = min(len(type(self).received) - 1, len(type(self).script) - 1)
        content = type(self).script[idx] if type(self).script else {"done": True, "summary": ""}
        payload = {
            "id": "stub",
            "object": "chat.completion",
            "model": body.get("model", "stub"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": json.dumps(content)},
                    "finish_reason": "stop",
                }
            ],
        }
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class StubBackend:
    """
    A running OpenAI-compatible endpoint that replays a scripted sequence of
    model turns. Only model inference is faked; everything else in the runtime
    is the real code path.

    Each script entry is the dict the "model" returns for that turn, e.g.
    {"tool": "list_tools", "args": {}, "reason": "..."} or
    {"done": True, "summary": "..."}. The last entry repeats if the runtime
    takes more turns than the script provides.
    """

    def __init__(self, base_url: str, handler_cls):
        self.base_url = base_url
        self._handler = handler_cls

    def set_script(self, script: list[dict]) -> None:
        self._handler.script = list(script)
        self._handler.received = []

    @property
    def received(self) -> list[dict]:
        """Raw request bodies the stub received, in order."""
        return self._handler.received

    def env(self) -> dict[str, str]:
        """Environment variables that point the runtime at this stub."""
        return {
            "AURO_MODEL_BACKEND": "openai_compatible",
            "AURO_OPENAI_BASE_URL": self.base_url,
            "AURO_OPENAI_MODEL": "stub-model",
        }


@pytest.fixture
def stub_backend():
    """A per-test stub model server on an ephemeral port."""
    handler_cls = type("_ScopedStubHandler", (_StubHandler,), {"script": [], "received": []})
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield StubBackend(f"http://127.0.0.1:{port}/v1", handler_cls)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def run_cli(repo_root: Path, stub_backend: StubBackend):
    """
    Run the real CLI against the stub backend and return the parsed RunResult.

        result = run_cli("tool_catalog", "list the tools",
                         script=[{"done": True, "summary": "ok"}])

    Returns (result_dict, completed_process). result_dict is None if stdout
    was not parseable JSON.
    """
    import os
    import subprocess

    def _run(directive_id: str, request: str, script: list[dict], timeout: int = 120):
        stub_backend.set_script(script)
        env = dict(os.environ)
        env.update(stub_backend.env())
        env["AURO_AUDIT_LOG"] = str(REPO_ROOT / "tests" / ".test_audit.jsonl")
        proc = subprocess.run(
            [sys.executable, "-m", "auro_runtime", "run", "--directive", directive_id, request, "--json"],
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        try:
            return json.loads(proc.stdout), proc
        except ValueError:
            return None, proc

    yield _run

    stray = REPO_ROOT / "tests" / ".test_audit.jsonl"
    if stray.exists():
        stray.unlink()
