"""
End-to-end tests: full directive runs through the real CLI subprocess.

Until this test file was written, auro-runtime had never completed a single
directive run — every invocation died at policy validation before a tool
could execute. These tests are the regression barrier against that ever
recurring, and against the two enforcement layers (directive scope, policy
guards) silently degrading or merging into one.

Every test here shells out to `python -m auro_runtime run ...` via the
`run_cli` fixture (see tests/conftest.py) against a scripted stub model
backend (`stub_backend`). Only model inference is faked — directive loading,
policy loading and validation, guard evaluation, and tool execution are all
the real code paths. Because each test spawns a subprocess, this module is
marked `slow`.
"""

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow


# --- Internal helpers --------------------------------------------------------


def _read_audit_events(repo_root: Path) -> list[dict]:
    """
    Read back the JSONL audit trail written by a run_cli() subprocess.

    run_cli points AURO_AUDIT_LOG at tests/.test_audit.jsonl for the
    subprocess's lifetime and deletes it in its own teardown, so this only
    ever reflects the run(s) made by the current test.
    """
    audit_path = repo_root / "tests" / ".test_audit.jsonl"
    if not audit_path.exists():
        return []
    events = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


# --- 1. Happy path: the runtime works at all ---------------------------------


def test_tool_catalog_happy_path_runs_to_completion(run_cli, registry):
    """
    Full pipeline: load directive -> load+validate policies -> LLM turn ->
    real tool execution -> LLM turn -> completion. Exercises two different
    real tools (list_tools, read_file) in one run so this doubles as
    confidence that ordinary sequential tool use works end to end.
    """
    result, proc = run_cli(
        "tool_catalog",
        "What tools are available?",
        script=[
            {"tool": "list_tools", "args": {"include_args": True}, "reason": "Survey the registry"},
            {"tool": "read_file", "args": {"path": "pyproject.toml"}, "reason": "Check project metadata"},
            {"done": True, "summary": "Here is the full tool catalog."},
        ],
    )

    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert result is not None, f"stdout was not JSON: {proc.stdout!r}"
    assert result["success"] is True
    assert result["error"] is None
    assert result["final_summary"] == "Here is the full tool catalog."

    steps = result["legacy_steps"]
    assert len(steps) == 2

    list_tools_step, read_file_step = steps
    assert list_tools_step["tool"] == "list_tools"
    assert list_tools_step["success"] is True
    assert list_tools_step["error"] is None

    tool_names = {t["name"] for t in list_tools_step["result"]["tools"]}
    assert tool_names == set(registry.keys()), "list_tools must return the real registered registry"
    assert len(tool_names) == 17, (
        "Expected the full 17-tool built-in registry. If this changed intentionally, "
        "update this count (and check whether it should have been gated by a directive)."
    )

    assert read_file_step["tool"] == "read_file"
    assert read_file_step["success"] is True
    assert 'name = "auro-runtime"' in read_file_step["result"]["content"], (
        "read_file should return the real file content from disk, not a stub"
    )


# --- 2. Policy text and tool allowlist actually reach the model prompt ------


def test_policy_and_tool_list_reach_the_system_prompt(run_cli, stub_backend):
    """
    Regression guard for a silent governance failure: if policy rule text or
    the directive's own tool allowlist ever stopped reaching the model, the
    model would run effectively unconstrained with nobody the wiser. Inspect
    the raw request body the stub server received rather than trusting the
    orchestrator's own bookkeeping.

    Also covers the zero-tool-call shape: a directive is allowed to finish
    without ever calling a tool.
    """
    result, proc = run_cli(
        "tool_catalog",
        "What tools are available?",
        script=[{"done": True, "summary": "no tools needed for this request"}],
    )

    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert result["success"] is True
    assert result["legacy_steps"] == []
    assert len(result["messages"]) == 2, "just the initial user message and the final assistant summary"

    assert len(stub_backend.received) == 1
    system_prompt = stub_backend.received[0]["messages"][0]["content"]

    # Policy content from policies/default.yaml actually present, not dropped.
    assert "no_delete_without_confirm" in system_prompt
    assert "Never emit a delete or overwrite tool call without explicit user confirmation" in system_prompt

    # The directive's own allowed-tool list is present (sorted, per orchestrator._run_impl).
    assert "Allowed tools for this directive: list_tools, read_file." in system_prompt

    # The directive body itself (not just front-matter metadata) reached the prompt.
    assert "# Tool catalog" in system_prompt
    assert "Read-only; no secrets." in system_prompt


# --- 3. Enforcement tier 1: directive scope ----------------------------------


def test_tool_not_in_directive_allowlist_is_rejected_and_run_completes(run_cli, repo_root, temp_output_file):
    """
    write_file is a real, registered tool, but tool_catalog's front matter
    only allows [list_tools, read_file]. The executor must reject the call
    before it ever reaches a policy guard or the filesystem, and the overall
    run must still finish cleanly (success + a real final summary) rather
    than crash — a bad tool choice by the model is not a fatal error.
    """
    blocked_path = temp_output_file("output/should_never_be_written.txt")

    result, proc = run_cli(
        "tool_catalog",
        "try to write a file",
        script=[
            {"tool": "write_file", "args": {"path": blocked_path, "content": "nope"}, "reason": "attempt an out-of-scope write"},
            {"done": True, "summary": "acknowledged: write_file is not available in this directive"},
        ],
    )

    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert result["success"] is True, "the run must complete even though the step failed"
    assert result["final_summary"] == "acknowledged: write_file is not available in this directive"

    steps = result["legacy_steps"]
    assert len(steps) == 1
    assert steps[0]["tool"] == "write_file"
    assert steps[0]["success"] is False
    assert "is not allowed by the current directive" in steps[0]["error"]

    assert not (repo_root / blocked_path).exists(), "a rejected tool call must never touch the filesystem"

    events = _read_audit_events(repo_root)
    tool_not_allowed = [e for e in events if e.get("event") == "tool_not_allowed"]
    assert len(tool_not_allowed) == 1
    assert tool_not_allowed[0]["tool"] == "write_file"
    # Tier-1 (directive scope) rejects before tier-2 (policy guards) ever runs.
    assert not any(e.get("event") == "policy_guard_check" for e in events)


# --- 4. Enforcement tier 2: policy guard -------------------------------------


def test_sensitive_path_read_is_blocked_by_policy_guard(run_cli, repo_root):
    """
    read_file IS allowed by tool_catalog's front matter, so a rejection here
    can only come from the sensitive_paths policy guard (policies/default.yaml,
    enforcement=block) — a different layer than directive scope. Confirms the
    two tiers are independent: tier 1 would have let this call through.
    """
    result, proc = run_cli(
        "tool_catalog",
        "read the secrets file",
        script=[
            {"tool": "read_file", "args": {"path": "auro_secrets.yaml"}, "reason": "peek at secrets"},
            {"done": True, "summary": "cannot read that file"},
        ],
    )

    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert result["success"] is True

    steps = result["legacy_steps"]
    assert len(steps) == 1
    assert steps[0]["tool"] == "read_file"
    assert steps[0]["success"] is False
    assert "Policy violation [sensitive_paths]" in steps[0]["error"]

    events = _read_audit_events(repo_root)
    guard_checks = [
        e for e in events if e.get("event") == "policy_guard_check" and e.get("rule_id") == "sensitive_paths"
    ]
    assert len(guard_checks) == 1
    assert guard_checks[0]["allowed"] is False
    assert guard_checks[0]["enforcement"] == "block"
    # Tier-1 (directive scope) never fires here — read_file IS in the allowed list.
    assert not any(e.get("event") == "tool_not_allowed" for e in events)


# --- 5. Warn-tier guard fires but never blocks -------------------------------


def test_warn_tier_guard_fires_but_does_not_block_bulk_writes(run_cli, repo_root, temp_output_file):
    """
    no_bulk_writes (policies/default.yaml) is bound at enforcement=warn.
    Writing to two distinct paths in one run must both succeed — a warn-tier
    guard observes and logs, it never blocks. Checked independently via the
    audit trail so a guard that was silently disabled (or never wired up)
    wouldn't be able to pass this test by accident.
    """
    path_a = temp_output_file("output/probe_a.txt")
    path_b = temp_output_file("output/probe_b.txt")

    result, proc = run_cli(
        "create_directive",
        "write two files to different paths",
        script=[
            {"tool": "write_file", "args": {"path": path_a, "content": "alpha"}, "reason": "first write"},
            {"tool": "write_file", "args": {"path": path_b, "content": "beta"}, "reason": "second write, different path"},
            {"done": True, "summary": "wrote both files"},
        ],
    )

    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert result["success"] is True

    steps = result["legacy_steps"]
    assert len(steps) == 2
    assert steps[0]["success"] is True and steps[0]["result"]["written"] is True
    assert steps[1]["success"] is True and steps[1]["result"]["written"] is True

    assert (repo_root / path_a).read_text(encoding="utf-8") == "alpha"
    assert (repo_root / path_b).read_text(encoding="utf-8") == "beta"

    events = _read_audit_events(repo_root)
    bulk_write_checks = [
        e for e in events if e.get("event") == "policy_guard_check" and e.get("rule_id") == "no_bulk_writes"
    ]
    assert len(bulk_write_checks) == 1, "the guard has no opinion on the first write, one verdict on the second"
    assert bulk_write_checks[0]["allowed"] is False, "it must actually flag the second, different-path write"
    assert bulk_write_checks[0]["enforcement"] == "warn"


# --- 6. Multi-step sequencing ------------------------------------------------


def test_multi_step_run_records_legacy_steps_in_order(run_cli):
    """A run with several sequential tool calls must produce legacy_steps in the same order."""
    result, proc = run_cli(
        "create_directive",
        "echo three things in sequence",
        script=[
            {"tool": "echo", "args": {"message": "first"}, "reason": "step 1"},
            {"tool": "echo", "args": {"message": "second"}, "reason": "step 2"},
            {"tool": "echo", "args": {"message": "third"}, "reason": "step 3"},
            {"done": True, "summary": "echoed three messages in order"},
        ],
    )

    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert result["success"] is True

    steps = result["legacy_steps"]
    assert len(steps) == 3
    assert [s["tool"] for s in steps] == ["echo", "echo", "echo"]
    assert [s["args"]["message"] for s in steps] == ["first", "second", "third"]
    assert [s["result"]["message"] for s in steps] == ["first", "second", "third"]
    assert all(s["success"] for s in steps)


# --- 7. max_steps termination -------------------------------------------------


def test_max_steps_terminates_a_never_ending_script(run_cli, stub_backend):
    """
    A model that keeps calling tools and never returns done must terminate
    rather than loop forever. run_cli does not expose --max-steps, so this
    exercises the CLI's real default (20): a one-entry script repeats for
    every turn per stub_backend's documented contract.
    """
    result, proc = run_cli(
        "create_directive",
        "loop forever",
        script=[{"tool": "echo", "args": {"message": "again"}, "reason": "keep going"}],
    )

    assert proc.returncode == 1
    assert result is not None, f"stdout was not JSON: {proc.stdout!r}"
    assert result["success"] is False
    assert "max steps" in result["error"].lower()
    assert result["meta"]["event"] == "max_steps_reached"
    assert result["meta"]["max_steps"] == 20

    steps = result["legacy_steps"]
    assert len(steps) == 20
    assert all(s["tool"] == "echo" and s["success"] for s in steps)
    assert len(stub_backend.received) == 20, "exactly one model call per step, no runaway extra calls"


# --- 8. Unknown directive id --------------------------------------------------


class TestCompletionShapeTolerance:
    """
    Smaller models signal `done` correctly but get the summary type wrong.

    Regression: a list-valued summary failed CompletionOutput validation, the
    exception was swallowed, and the run then fell through to tool-call parsing
    and died reporting "invalid tool call shape" — pointing at entirely the
    wrong problem. Found by running a local 3B model against the real CLI.
    """

    def test_summary_as_list_of_strings_is_accepted(self):
        from auro_runtime.schemas import CompletionOutput

        c = CompletionOutput.model_validate({"done": True, "summary": ["one", "two"]})
        assert c.done is True
        assert "one" in c.summary and "two" in c.summary

    def test_summary_as_list_of_dicts_is_accepted(self):
        from auro_runtime.schemas import CompletionOutput

        c = CompletionOutput.model_validate(
            {"done": True, "summary": [{"name": "list_dir", "args": "path (str)"}]}
        )
        assert "list_dir" in c.summary

    def test_summary_as_dict_is_accepted(self):
        from auro_runtime.schemas import CompletionOutput

        c = CompletionOutput.model_validate({"done": True, "summary": {"result": "ok"}})
        assert "ok" in c.summary

    def test_summary_none_becomes_empty_string(self):
        from auro_runtime.schemas import CompletionOutput

        assert CompletionOutput.model_validate({"done": True, "summary": None}).summary == ""

    def test_plain_string_summary_is_unchanged(self):
        from auro_runtime.schemas import CompletionOutput

        assert CompletionOutput.model_validate({"done": True, "summary": "hi"}).summary == "hi"

    def test_run_completes_when_model_returns_a_list_summary(self, run_cli):
        """End to end: the shape a real 3B model produced must not kill the run."""
        result, proc = run_cli(
            "tool_catalog",
            "list the tools",
            script=[{"done": True, "summary": [{"name": "list_dir"}, {"name": "read_file"}]}],
        )
        assert result is not None, proc.stdout + proc.stderr
        assert result["success"] is True, result.get("error")
        assert result["meta"]["event"] == "done"
        assert "list_dir" in (result["final_summary"] or "")


def test_unknown_directive_id_produces_clean_error_not_traceback(run_cli, stub_backend):
    """An unknown --directive id should fail gracefully with a structured error, not a stack trace."""
    result, proc = run_cli(
        "this_directive_does_not_exist_xyz",
        "hello",
        script=[{"done": True, "summary": "unreachable"}],
    )

    assert "Traceback" not in proc.stderr, f"CLI crashed instead of returning a clean error:\n{proc.stderr}"
    assert result is not None, f"stdout should be valid JSON even on failure; got {proc.stdout!r}"
    assert result["success"] is False
    assert result["error"]
    assert stub_backend.received == [], "the model should never be contacted for an unroutable directive id"


# --- 9. Malformed model output (not JSON at all) -----------------------------


def test_malformed_non_json_model_output_fails_cleanly(run_cli):
    """
    A model turn that isn't JSON at all — no tool call, no completion — must be
    a clean parse failure, not an unhandled exception.

    stub_backend.set_script() is typed as list[dict], and each entry is normally
    fed through json.dumps() to become the assistant message content. Python
    does not enforce that type hint at runtime: passing a plain string entry
    still round-trips correctly (json.dumps("text") -> the outer HTTP response
    JSON decodes back to the exact original string as the message content), so
    the "model" ends up returning genuinely non-JSON text without needing any
    change to conftest.py.
    """
    result, proc = run_cli(
        "tool_catalog",
        "list the tools",
        script=["I refuse to output JSON today."],  # deliberately not a dict; see docstring
    )

    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert result is not None, f"stdout was not JSON: {proc.stdout!r}"
    assert result["success"] is False
    assert "Could not parse LLM response as JSON" in result["error"]
    assert result["meta"]["event"] == "parse_json_failed"
    assert result["legacy_steps"] == []


# --- 10. Backend selection ----------------------------------------------------


def test_backend_selection_uses_openai_compatible_stub_with_configured_model(run_cli, stub_backend):
    """
    Confirm the run actually goes through the OpenAI-compatible backend
    (auro_runtime.models.openai_compatible_backend), not some other path:
    one HTTP call per turn, each carrying the model name from
    AURO_OPENAI_MODEL and an OpenAI chat-completions-shaped system/user
    message pair.
    """
    result, proc = run_cli(
        "tool_catalog",
        "what tools exist?",
        script=[
            {"tool": "list_tools", "args": {"include_args": False}, "reason": "survey tools"},
            {"done": True, "summary": "there are 17 tools"},
        ],
    )

    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert result["success"] is True

    assert len(stub_backend.received) == 2, "one HTTP request per orchestrator turn"
    for call in stub_backend.received:
        assert call["model"] == "stub-model", "must use the model from AURO_OPENAI_MODEL"
        roles = [m["role"] for m in call["messages"]]
        assert roles == ["system", "user"]


# --- Bonus: a third, distinct validation layer -------------------------------


def test_invalid_tool_arguments_are_rejected_by_schema_validation(run_cli, repo_root, temp_output_file):
    """
    A third validation layer, distinct from directive scope (tier 1) and
    policy guards (tier 2): per-tool Pydantic argument schemas. write_file
    IS allowed by create_directive and no policy guard cares about a missing
    field, but WriteFileArgs requires `content` — calling it without one must
    fail schema validation cleanly rather than crashing the whole run.
    """
    probe_path = temp_output_file("output/schema_probe.txt")

    result, proc = run_cli(
        "create_directive",
        "write a file but forget the content",
        script=[
            {"tool": "write_file", "args": {"path": probe_path}, "reason": "missing content on purpose"},
            {"done": True, "summary": "acknowledged the validation error"},
        ],
    )

    assert proc.returncode == 0, f"stderr: {proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert result["success"] is True

    steps = result["legacy_steps"]
    assert len(steps) == 1
    assert steps[0]["tool"] == "write_file"
    assert steps[0]["success"] is False
    assert "Invalid arguments for write_file" in steps[0]["error"]
    assert "content" in steps[0]["error"]

    assert not (repo_root / probe_path).exists(), "a schema-rejected call must never touch the filesystem"
