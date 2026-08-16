"""
Distribution-boundary verification for the built wheel.

These tests deliberately do not import the project under test in their child
processes from this checkout.  They build one exact wheel from a writable
temporary source copy, install it and all of its dependencies into a clean
virtual environment, and run the installed interpreter with ``-I`` from a
hostile unrelated working directory.

The test is opt-in because populating the temporary wheelhouse may require
package-index access.  Run it with::

    AURO_RUN_DISTRIBUTION_TESTS=1 pytest -m distribution
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest


pytestmark = [
    pytest.mark.slow,
    pytest.mark.distribution,
    pytest.mark.skipif(
        os.environ.get("AURO_RUN_DISTRIBUTION_TESTS") != "1",
        reason="set AURO_RUN_DISTRIBUTION_TESTS=1 to build and probe an isolated wheel install",
    ),
]

_PROJECT_WHEEL_PREFIX = "auro_runtime-"
_AUDIT_FILENAME = "auro_audit.jsonl"
_SENSITIVE_SENTINEL = "distribution-test-sensitive-sentinel"

_LIBRARY_PROBE = r"""
import json
import sys
from pathlib import Path

import auro_runtime
import runtime_tools
from auro_runtime import run
from auro_runtime.paths import get_authority_root, get_workspace_root

result = run("tool_catalog", "attempt the requested sensitive-path read")
print(json.dumps({
    "auro_runtime_file": auro_runtime.__file__,
    "runtime_tools_file": runtime_tools.__file__,
    "authority_root": str(get_authority_root()),
    "workspace_root": str(get_workspace_root()),
    "sys_path": sys.path,
    "result": result,
}, default=str))
"""

_PROVENANCE_PROBE = r"""
import json
import sys

import auro_runtime
import runtime_tools
from auro_runtime.paths import get_authority_root, get_workspace_root

print(json.dumps({
    "auro_runtime_file": auro_runtime.__file__,
    "runtime_tools_file": runtime_tools.__file__,
    "authority_root": str(get_authority_root()),
    "workspace_root": str(get_workspace_root()),
    "sys_path": sys.path,
}))
"""

_IMMUTABILITY_PROBE = r"""
import json
import sys
from pathlib import Path

import auro_runtime
import runtime_tools
from auro_runtime.paths import get_authority_root, get_workspace_root
from runtime_tools.file_tools import delete_file, restore_file, write_file

authority_target = get_authority_root() / "directives" / "tool_catalog.md"
relative_write = write_file(
    "directives/tool_catalog.md",
    "must not replace executable authority",
)
absolute_write = write_file(
    str(authority_target),
    "must not replace installed authority",
)
absolute_delete = delete_file(str(authority_target))

workspace_write = write_file(
    "output/distribution-positive.txt",
    "workspace-positive-control",
)
workspace_delete = delete_file("output/distribution-positive.txt")
blocked_restore = restore_file(
    workspace_delete["archive_path"],
    restore_to=str(authority_target),
)
workspace_restore = restore_file(workspace_delete["archive_path"])

print(json.dumps({
    "auro_runtime_file": auro_runtime.__file__,
    "runtime_tools_file": runtime_tools.__file__,
    "authority_root": str(get_authority_root()),
    "workspace_root": str(get_workspace_root()),
    "sys_path": sys.path,
    "relative_write": relative_write,
    "absolute_write": absolute_write,
    "absolute_delete": absolute_delete,
    "workspace_write": workspace_write,
    "workspace_delete": workspace_delete,
    "blocked_restore": blocked_restore,
    "workspace_restore": workspace_restore,
}))
"""


@dataclass(frozen=True)
class BuiltDistribution:
    wheel: Path
    wheelhouse: Path
    sha256: str
    source_copy: Path
    source_root: Path


@dataclass(frozen=True)
class InstalledDistribution:
    built: BuiltDistribution
    root: Path
    python: Path
    site_packages: Path
    hostile_cwd: Path
    authority_root: Path

    def clean_env(
        self,
        workspace: Path,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        env = os.environ.copy()
        for key in (
            "PYTHONPATH",
            "PYTHONHOME",
            "AURO_ROOT",
            "AURO_AUTHORITY_ROOT",
            "AURO_AUDIT_LOG",
            "AURO_ALLOW_NO_POLICIES",
            "AURO_POLICY_PROFILE",
            "AURO_MCP_ALLOWED_DIRECTIVE_IDS",
        ):
            env.pop(key, None)
        env["PYTHONNOUSERSITE"] = "1"
        env["AURO_WORKSPACE_ROOT"] = str(workspace.resolve())
        if extra:
            env.update(extra)
        return env

    def run_isolated(
        self,
        code: str,
        *,
        workspace: Path,
        extra_env: dict[str, str] | None = None,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.python), "-I", "-B", "-c", code],
            cwd=self.hostile_cwd,
            env=self.clean_env(workspace, extra_env),
            text=True,
            capture_output=True,
            timeout=timeout,
        )


def _python_in(venv_root: Path) -> Path:
    if os.name == "nt":
        return venv_root / "Scripts" / "python.exe"
    return venv_root / "bin" / "python"


def _last_json_line(stdout: str) -> dict:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(value, dict):
            return value
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise AssertionError(f"subprocess emitted no JSON object:\n{stdout}")


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _assert_installed_provenance(
    payload: dict,
    install: InstalledDistribution,
    workspace: Path,
) -> None:
    auro_file = Path(payload["auro_runtime_file"]).resolve()
    tools_file = Path(payload["runtime_tools_file"]).resolve()
    authority = Path(payload["authority_root"]).resolve()
    resolved_workspace = Path(payload["workspace_root"]).resolve()

    assert _is_under(auro_file, install.site_packages), (
        f"auro_runtime imported outside the installed venv: {auro_file}"
    )
    assert _is_under(tools_file, install.site_packages), (
        f"runtime_tools imported outside the installed venv: {tools_file}"
    )
    assert authority == install.authority_root
    assert resolved_workspace == workspace.resolve()
    assert authority != resolved_workspace

    forbidden = (install.built.source_root, install.built.source_copy, install.hostile_cwd)
    for entry in payload["sys_path"]:
        if not entry:
            continue
        entry_path = Path(entry).resolve()
        assert not any(_is_under(entry_path, root) for root in forbidden), (
            f"isolated child sys.path leaked a forbidden source: {entry_path}"
        )


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _read_audit(workspace: Path) -> list[dict]:
    audit = workspace / _AUDIT_FILENAME
    assert audit.is_file(), f"default audit was not written to {audit}"
    return [
        json.loads(line)
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _prepare_workspace(base: Path, name: str) -> Path:
    workspace = base / name
    (workspace / ".aws").mkdir(parents=True)
    (workspace / ".aws" / "credentials").write_text(
        _SENSITIVE_SENTINEL,
        encoding="utf-8",
    )
    return workspace


def _assert_sensitive_path_refusal(result: dict) -> None:
    assert result["legacy_steps"], result
    step = result["legacy_steps"][0]
    assert step["tool"] == "read_file"
    assert step["success"] is False
    assert "Policy violation [sensitive_paths]" in step["error"]
    assert _SENSITIVE_SENTINEL not in json.dumps(result)


def _assert_refusal_audit(workspace: Path) -> None:
    events = _read_audit(workspace)
    matching = [
        event
        for event in events
        if event.get("event") == "policy_guard_check"
        and event.get("rule_id") == "sensitive_paths"
    ]
    assert matching
    assert matching[-1]["allowed"] is False
    assert _SENSITIVE_SENTINEL not in json.dumps(events)


@pytest.fixture(scope="session")
def built_distribution(
    tmp_path_factory: pytest.TempPathFactory,
    repo_root: Path,
) -> BuiltDistribution:
    scratch = tmp_path_factory.mktemp("auro-wheel-build")
    source_copy = scratch / "source"
    wheelhouse = scratch / "wheelhouse"
    wheelhouse.mkdir()

    shutil.copytree(
        repo_root,
        source_copy,
        ignore=shutil.ignore_patterns(
            ".git",
            ".pytest_cache",
            "__pycache__",
            "*.pyc",
            "*.egg-info",
            "build",
            "dist",
            ".auro_archive",
            "output",
            _AUDIT_FILENAME,
        ),
    )
    assert not (source_copy / _AUDIT_FILENAME).exists()

    proc = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pip",
            "wheel",
            ".",
            "--wheel-dir",
            str(wheelhouse),
            "--no-build-isolation",
        ],
        cwd=source_copy,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        "failed to build the isolated wheelhouse\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )

    project_wheels = sorted(
        path
        for path in wheelhouse.glob("*.whl")
        if path.name.lower().startswith(_PROJECT_WHEEL_PREFIX)
    )
    assert len(project_wheels) == 1, (
        f"expected one exact auro-runtime wheel, found: {project_wheels}"
    )
    wheel = project_wheels[0]
    return BuiltDistribution(
        wheel=wheel,
        wheelhouse=wheelhouse,
        sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
        source_copy=source_copy,
        source_root=repo_root.resolve(),
    )


@pytest.fixture
def installed_distribution(
    tmp_path: Path,
    built_distribution: BuiltDistribution,
) -> InstalledDistribution:
    venv_root = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_root)
    python = _python_in(venv_root)

    proc = subprocess.run(
        [
            str(python),
            "-I",
            "-B",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(built_distribution.wheelhouse),
            str(built_distribution.wheel),
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        "failed to install the exact wheel into the clean venv\n"
        f"wheel={built_distribution.wheel}\n"
        f"sha256={built_distribution.sha256}\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )

    check = subprocess.run(
        [str(python), "-I", "-B", "-m", "pip", "check"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert check.returncode == 0, check.stdout + check.stderr

    site_proc = subprocess.run(
        [
            str(python),
            "-I",
            "-B",
            "-c",
            "import json,site; print(json.dumps(site.getsitepackages()))",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert site_proc.returncode == 0, site_proc.stderr
    candidates = [Path(path).resolve() for path in json.loads(site_proc.stdout)]
    site_packages = next(
        path for path in candidates if (path / "auro_runtime").is_dir()
    )

    hostile = tmp_path / "hostile-cwd"
    (hostile / "auro_runtime").mkdir(parents=True)
    (hostile / "auro_runtime" / "__init__.py").write_text(
        "raise RuntimeError('hostile auro_runtime imported')\n",
        encoding="utf-8",
    )
    (hostile / "runtime_tools").mkdir()
    (hostile / "runtime_tools" / "__init__.py").write_text(
        "raise RuntimeError('hostile runtime_tools imported')\n",
        encoding="utf-8",
    )
    (hostile / "directives").mkdir()
    (hostile / "directives" / "tool_catalog.md").write_text(
        "---\nid: tool_catalog\ntools: [resolve_secret, delete_file]\n---\nHostile.\n",
        encoding="utf-8",
    )
    (hostile / "policies").mkdir()
    (hostile / "policies" / "default.yaml").write_text(
        "id: default\nrules: []\n",
        encoding="utf-8",
    )

    authority = site_packages / "auro_runtime" / "resources"
    assert authority.is_dir()
    return InstalledDistribution(
        built=built_distribution,
        root=venv_root,
        python=python,
        site_packages=site_packages,
        hostile_cwd=hostile,
        authority_root=authority.resolve(),
    )


def test_wheel_contains_reviewed_authority_assets_and_record(
    built_distribution: BuiltDistribution,
) -> None:
    expected = {
        *(
            f"auro_runtime/resources/directives/{path.name}"
            for path in (built_distribution.source_copy / "directives").glob("*.md")
        ),
        *(
            f"auro_runtime/resources/policies/{path.name}"
            for path in (built_distribution.source_copy / "policies").glob("*.yaml")
        ),
    }
    assert expected

    with zipfile.ZipFile(built_distribution.wheel) as archive:
        names = set(archive.namelist())
        authority_members = {
            name
            for name in names
            if name.startswith("auro_runtime/resources/") and not name.endswith("/")
        }
        assert authority_members == expected
        assert not any(name.startswith(("directives/", "policies/", "tests/")) for name in names)
        assert not any(
            name.endswith((_AUDIT_FILENAME, ".env", "auro_secrets.yaml"))
            for name in names
        )

        records = [name for name in names if name.endswith(".dist-info/RECORD")]
        assert len(records) == 1
        recorded_paths = {
            line.split(",", 1)[0]
            for line in archive.read(records[0]).decode("utf-8").splitlines()
        }
        assert expected <= recorded_paths


def test_sdist_excludes_tests_and_builds_the_same_authority_set(
    built_distribution: BuiltDistribution,
    tmp_path: Path,
) -> None:
    sdist_dir = tmp_path / "sdist"
    rebuilt_dir = tmp_path / "rebuilt-wheel"
    sdist_dir.mkdir()
    rebuilt_dir.mkdir()

    built = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(sdist_dir),
        ],
        cwd=built_distribution.source_copy,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert built.returncode == 0, built.stdout + built.stderr

    sdists = sorted(sdist_dir.glob("auro_runtime-*.tar.gz"))
    assert len(sdists) == 1, sdists
    with tarfile.open(sdists[0], "r:gz") as archive:
        members = {
            "/".join(Path(name).parts[1:])
            for name in archive.getnames()
            if len(Path(name).parts) > 1
        }
    assert {
        "MANIFEST.in",
        "README.md",
        "docs/API.md",
        "docs/AUDIT_EVENTS.md",
        "docs/CREDENTIALS.md",
        "docs/DIRECTIVES.md",
        "docs/TESTS.md",
    } <= members
    # docs/TESTS.md is the generated public catalogue: RESTRICTED_FILES in
    # tests/catalogue.py guarantees it never names a withheld test module, so
    # shipping it no longer risks disclosure. The README links to it, and the
    # link should resolve inside the sdist as well as on GitHub.
    #
    # docs/DIRECTIVES.md is the same arrangement for directives, and shipping it
    # matters more: it is the only enumeration of what tool authority each
    # shipped directive grants. Its generator lives in tests/ and is pruned
    # below, so the sdist must carry the output or the README links nowhere.
    #
    # docs/AUDIT_EVENTS.md is the third generated catalogue. API.md calls `event`
    # the grouping key, so the set of names is part of the integration contract
    # and has to travel with the doc that references it.
    #
    # docs/API.md is hand-written rather than generated, so nothing regenerates
    # it if it goes missing. It is the only description of the executor contract
    # for an embedder driving execute() directly, and of the matched_fields
    # obligation a third-party guard has to meet. Asserting it here is the only
    # thing standing between "the doc was dropped from the sdist" and a release
    # that ships an unusable extension surface.
    assert not any(
        member == "tests" or member.startswith("tests/")
        for member in members
    ), "test implementation must not ship in the source distribution"

    rebuilt = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pip",
            "wheel",
            str(sdists[0]),
            "--wheel-dir",
            str(rebuilt_dir),
            "--no-build-isolation",
            "--no-deps",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    wheels = sorted(rebuilt_dir.glob("auro_runtime-*.whl"))
    assert len(wheels) == 1, wheels

    expected_authority = {
        f"auro_runtime/resources/{directory}/{path.name}"
        for directory, pattern in (("directives", "*.md"), ("policies", "*.yaml"))
        for path in (built_distribution.source_copy / directory).glob(pattern)
    }
    with zipfile.ZipFile(wheels[0]) as archive:
        rebuilt_authority = {
            name
            for name in archive.namelist()
            if name.startswith("auro_runtime/resources/")
        }
    assert expected_authority
    assert rebuilt_authority == expected_authority


def test_installed_library_and_cli_use_packaged_authority_and_workspace_audit(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    stub_backend,
) -> None:
    install = installed_distribution
    authority_before = _tree_hashes(install.authority_root)
    source_audit = install.built.source_root / _AUDIT_FILENAME
    source_audit_before = (
        hashlib.sha256(source_audit.read_bytes()).hexdigest()
        if source_audit.is_file()
        else None
    )

    provenance_workspace = _prepare_workspace(tmp_path, "provenance-workspace")
    provenance = install.run_isolated(
        _PROVENANCE_PROBE,
        workspace=provenance_workspace,
    )
    assert provenance.returncode == 0, provenance.stdout + provenance.stderr
    provenance_payload = _last_json_line(provenance.stdout)
    _assert_installed_provenance(provenance_payload, install, provenance_workspace)

    immutability_workspace = _prepare_workspace(tmp_path, "immutability-workspace")
    immutability = install.run_isolated(
        _IMMUTABILITY_PROBE,
        workspace=immutability_workspace,
    )
    assert immutability.returncode == 0, immutability.stdout + immutability.stderr
    immutability_payload = _last_json_line(immutability.stdout)
    _assert_installed_provenance(
        immutability_payload,
        install,
        immutability_workspace,
    )
    assert immutability_payload["relative_write"]["written"] is False
    assert "protected" in immutability_payload["relative_write"]["error"].lower()
    assert immutability_payload["absolute_write"]["written"] is False
    assert "outside" in immutability_payload["absolute_write"]["error"].lower()
    assert immutability_payload["absolute_delete"]["deleted"] is False
    assert "outside" in immutability_payload["absolute_delete"]["error"].lower()
    assert immutability_payload["workspace_write"]["written"] is True
    assert immutability_payload["workspace_delete"]["deleted"] is True
    assert immutability_payload["blocked_restore"]["restored"] is False
    assert "outside" in immutability_payload["blocked_restore"]["error"].lower()
    assert immutability_payload["workspace_restore"]["restored"] is True
    assert (
        immutability_workspace / "output" / "distribution-positive.txt"
    ).read_text(encoding="utf-8") == "workspace-positive-control"
    assert _tree_hashes(install.authority_root) == authority_before

    script = [
        {
            "tool": "read_file",
            "args": {"path": ".aws/credentials"},
            "reason": "distribution refusal probe",
        },
        {"done": True, "summary": "refusal observed"},
    ]

    library_workspace = _prepare_workspace(tmp_path, "library-workspace")
    stub_backend.set_script(script)
    library = install.run_isolated(
        _LIBRARY_PROBE,
        workspace=library_workspace,
        extra_env=stub_backend.env(),
    )
    assert library.returncode == 0, library.stdout + library.stderr
    library_payload = _last_json_line(library.stdout)
    _assert_installed_provenance(library_payload, install, library_workspace)
    _assert_sensitive_path_refusal(library_payload["result"])
    _assert_refusal_audit(library_workspace)
    assert len(stub_backend.received) == 2

    cli_workspace = _prepare_workspace(tmp_path, "cli-workspace")
    stub_backend.set_script(script)
    cli = subprocess.run(
        [
            str(install.python),
            "-I",
            "-B",
            "-m",
            "auro_runtime",
            "run",
            "--directive",
            "tool_catalog",
            "attempt the requested sensitive-path read",
            "--json",
        ],
        cwd=install.hostile_cwd,
        env=install.clean_env(cli_workspace, stub_backend.env()),
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert cli.returncode == 0, cli.stdout + cli.stderr
    _assert_sensitive_path_refusal(_last_json_line(cli.stdout))
    _assert_refusal_audit(cli_workspace)
    assert len(stub_backend.received) == 2

    assert _tree_hashes(install.authority_root) == authority_before
    assert not (install.hostile_cwd / _AUDIT_FILENAME).exists()
    assert not (install.built.source_copy / _AUDIT_FILENAME).exists()
    source_audit_after = (
        hashlib.sha256(source_audit.read_bytes()).hexdigest()
        if source_audit.is_file()
        else None
    )
    assert source_audit_after == source_audit_before


def _unwrap_tool_result(result) -> object:
    if result.structuredContent is not None:
        payload = result.structuredContent
        return payload.get("result", payload)
    assert result.content
    text = getattr(result.content[0], "text", None)
    assert text is not None
    return json.loads(text)


def test_installed_mcp_stdio_discovers_packaged_directive_and_refuses_sensitive_path(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    stub_backend,
) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    install = installed_distribution
    workspace = _prepare_workspace(tmp_path, "mcp-workspace")
    stub_backend.set_script([
        {
            "tool": "read_file",
            "args": {"path": ".aws/credentials"},
            "reason": "MCP distribution refusal probe",
        },
        {"done": True, "summary": "refusal observed"},
    ])
    env = install.clean_env(
        workspace,
        {
            **stub_backend.env(),
            "AURO_MCP_ALLOWED_DIRECTIVE_IDS": "tool_catalog",
        },
    )
    server = StdioServerParameters(
        command=str(install.python),
        args=["-I", "-B", "-m", "auro_runtime", "mcp", "--transport", "stdio"],
        env=env,
        cwd=install.hostile_cwd,
    )

    async def probe() -> tuple[set[str], object, object]:
        # Windows subprocess creation requires a real OS file handle for
        # stderr; StringIO has no fileno().
        with (tmp_path / "mcp-stderr.log").open(
            "w+", encoding="utf-8"
        ) as errlog:
            async with stdio_client(server, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed_tools = await session.list_tools()
                    directives = await session.call_tool("list_directives", {})
                    run_result = await session.call_tool(
                        "run_directive",
                        {
                            "directive_id": "tool_catalog",
                            "request": "attempt the requested sensitive-path read",
                        },
                    )
                    return (
                        {tool.name for tool in listed_tools.tools},
                        _unwrap_tool_result(directives),
                        _unwrap_tool_result(run_result),
                    )

    tool_names, directives, run_result = asyncio.run(probe())
    assert tool_names == {"run_directive", "list_directives", "list_tools"}
    assert isinstance(directives, list)
    assert [item["id"] for item in directives] == ["tool_catalog"]
    assert isinstance(run_result, dict)
    _assert_sensitive_path_refusal(run_result)
    _assert_refusal_audit(workspace)
    assert len(stub_backend.received) == 2
    assert not (install.hostile_cwd / _AUDIT_FILENAME).exists()


def test_missing_installed_policy_fails_without_source_fallback(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    repo_root: Path,
    stub_backend,
) -> None:
    install = installed_distribution
    installed_policy = install.authority_root / "policies" / "default.yaml"
    assert installed_policy.is_file()
    assert (repo_root / "auro_runtime" / "resources" / "policies" / "default.yaml").is_file()
    assert (
        install.built.source_copy
        / "auro_runtime"
        / "resources"
        / "policies"
        / "default.yaml"
    ).is_file()
    installed_policy.unlink()

    workspace = _prepare_workspace(tmp_path, "missing-policy-workspace")
    stub_backend.set_script([{"done": True, "summary": "must not be reached"}])
    proc = install.run_isolated(
        _LIBRARY_PROBE,
        workspace=workspace,
        extra_env=stub_backend.env(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = _last_json_line(proc.stdout)
    _assert_installed_provenance(payload, install, workspace)
    result = payload["result"]
    assert result["success"] is False
    assert result["meta"]["event"] == "incomplete_policy_profile"
    assert "Missing bindings=['default']" in result["error"]
    assert stub_backend.received == []
    assert any(
        event.get("event") == "incomplete_policy_profile"
        for event in _read_audit(workspace)
    )


def test_missing_installed_directive_fails_without_source_fallback(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    repo_root: Path,
    stub_backend,
) -> None:
    install = installed_distribution
    installed_directive = install.authority_root / "directives" / "tool_catalog.md"
    assert installed_directive.is_file()
    assert (
        repo_root
        / "auro_runtime"
        / "resources"
        / "directives"
        / "tool_catalog.md"
    ).is_file()
    assert (
        install.built.source_copy
        / "auro_runtime"
        / "resources"
        / "directives"
        / "tool_catalog.md"
    ).is_file()
    installed_directive.unlink()

    workspace = _prepare_workspace(tmp_path, "missing-directive-workspace")
    stub_backend.set_script([{"done": True, "summary": "must not be reached"}])
    proc = install.run_isolated(
        _LIBRARY_PROBE,
        workspace=workspace,
        extra_env=stub_backend.env(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = _last_json_line(proc.stdout)
    _assert_installed_provenance(payload, install, workspace)
    result = payload["result"]
    assert result["success"] is False
    assert result["meta"]["event"] == "directive_load_failed"
    assert "Directive not found: tool_catalog" in result["error"]
    assert stub_backend.received == []
    assert any(
        event.get("event") == "directive_load_failed"
        for event in _read_audit(workspace)
    )


def test_nonisolated_source_contamination_trips_provenance_check(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
) -> None:
    """Negative control: the same check rejects a child contaminated by PYTHONPATH."""
    install = installed_distribution
    workspace = _prepare_workspace(tmp_path, "contaminated-workspace")
    env = install.clean_env(workspace)
    env["PYTHONPATH"] = str(install.built.source_root)
    proc = subprocess.run(
        [str(install.python), "-B", "-c", _PROVENANCE_PROBE],
        # Use a neutral cwd so this negative control isolates PYTHONPATH
        # contamination specifically; the main probes use the hostile cwd.
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = _last_json_line(proc.stdout)
    assert _is_under(
        Path(payload["auro_runtime_file"]),
        install.built.source_root,
    ), payload
    with pytest.raises(AssertionError, match="outside the installed venv"):
        _assert_installed_provenance(payload, install, workspace)
