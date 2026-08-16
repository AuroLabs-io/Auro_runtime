"""Adversarial regression tests for the two 2026-07-26 P0 security seams.

Every refusal test has a positive control.  These tests exercise public
boundaries or the exact authority hand-off rather than merely scanning source.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clear_cached_workspace_resolution():
    """Environment-changing path tests must not leak process-cached workspace state."""
    from auro_runtime.paths import get_workspace_root

    get_workspace_root.cache_clear()
    yield
    get_workspace_root.cache_clear()


def _audit_to_tmp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AURO_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


@pytest.mark.parametrize("value", [None, "", "0", "false", " ", "yes", "typo"])
def test_zero_policy_gate_rejects_every_non_explicit_opt_in(
    monkeypatch, tmp_path, value
):
    """Only the exact documented value ``1`` may disable every policy guard."""
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    policies_dir = tmp_path / "empty-policies"
    policies_dir.mkdir()
    if value is None:
        monkeypatch.delenv("AURO_ALLOW_NO_POLICIES", raising=False)
    else:
        monkeypatch.setenv("AURO_ALLOW_NO_POLICIES", value)

    def model_must_not_run(*_args, **_kwargs):
        pytest.fail("the model ran before the zero-policy posture was refused")

    monkeypatch.setattr(orchestrator, "generate", model_must_not_run)
    result = orchestrator.run(
        "tool_catalog",
        "probe the zero-policy gate",
        policies_dir=policies_dir,
    )

    assert result["success"] is False
    assert result["meta"]["event"] == "no_enforceable_policies"
    assert "No enforceable policy rules" in result["error"]


def test_zero_policy_gate_allows_exact_explicit_opt_in(monkeypatch, tmp_path):
    """Positive control: the documented escape hatch remains usable."""
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    policies_dir = tmp_path / "empty-policies"
    policies_dir.mkdir()
    monkeypatch.setenv("AURO_ALLOW_NO_POLICIES", "1")
    monkeypatch.setattr(
        orchestrator,
        "generate",
        lambda *_args, **_kwargs: '{"done": true, "summary": "explicitly unguarded"}',
    )

    result = orchestrator.run(
        "tool_catalog",
        "positive control",
        policies_dir=policies_dir,
    )

    assert result["success"] is True
    assert result["final_summary"] == "explicitly unguarded"


def test_a_missing_policies_directory_is_refused_even_with_the_opt_in_set(
    monkeypatch, tmp_path
):
    """
    The compound case: AURO_ALLOW_NO_POLICIES=1 left in an environment, plus a
    mistyped policies_dir, must not silently become an unguarded run.

    load_policies() returns [] for a missing directory and for an empty one, so
    the zero-rules gate alone cannot tell a typo from a deliberate posture. A
    path that is not there is a configuration error, and no value of the opt-in
    makes it the operator's intent.
    """
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    missing = tmp_path / "policies-typo"
    assert not missing.exists(), "the probe must point at a path that is not there"
    monkeypatch.setenv("AURO_ALLOW_NO_POLICIES", "1")

    def model_must_not_run(*_args, **_kwargs):
        pytest.fail("the model ran before the missing policies directory was refused")

    monkeypatch.setattr(orchestrator, "generate", model_must_not_run)
    result = orchestrator.run(
        "tool_catalog",
        "probe the missing-directory case",
        policies_dir=missing,
    )

    assert result["success"] is False
    assert result["meta"]["event"] == "policies_dir_missing", (
        "a missing directory must refuse on its own terms, not as a zero-rules posture"
    )
    assert "does not exist" in result["error"]


def test_an_existing_empty_policies_directory_still_honours_the_opt_in(
    monkeypatch, tmp_path
):
    """
    Negative control for the test above. The missing-directory refusal must not
    swallow the deliberate case: an operator who really wants an unguarded run
    against a directory that exists still gets one.
    """
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    present = tmp_path / "deliberately-empty"
    present.mkdir()
    monkeypatch.setenv("AURO_ALLOW_NO_POLICIES", "1")
    monkeypatch.setattr(
        orchestrator,
        "generate",
        lambda *_args, **_kwargs: '{"done": true, "summary": "explicitly unguarded"}',
    )

    result = orchestrator.run(
        "tool_catalog",
        "negative control",
        policies_dir=present,
    )

    assert result["success"] is True
    assert result["final_summary"] == "explicitly unguarded"


def _copy_shipped_policies(repo_root, dest):
    dest.mkdir(exist_ok=True)
    for path in (repo_root / "policies").glob("*.yaml"):
        (dest / path.name).write_bytes(path.read_bytes())
    return dest


def test_a_downgraded_shipped_rule_is_refused_at_runtime(monkeypatch, tmp_path, repo_root):
    """
    The edit that hides: `block` to `advisory` keeps the rule id, so the profile
    check passed it while the rule stopped reaching the executor entirely.

    `no_secrets_in_logs` is the rule that keeps credentials out of the audit log
    via tool arguments, which is why it is the one probed here.
    """
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    policies_dir = _copy_shipped_policies(repo_root, tmp_path / "downgraded")
    target = policies_dir / "default.yaml"
    text = target.read_text(encoding="utf-8")
    assert "enforcement: block" in text, "shipped default.yaml no longer has a blocking rule"
    target.write_text(
        text.replace("enforcement: block", "enforcement: advisory", 1),
        encoding="utf-8",
    )
    monkeypatch.delenv("AURO_POLICY_PROFILE", raising=False)

    def model_must_not_run(*_args, **_kwargs):
        pytest.fail("the model ran under a downgraded policy posture")

    monkeypatch.setattr(orchestrator, "generate", model_must_not_run)
    result = orchestrator.run(
        "tool_catalog",
        "probe a downgraded shipped rule",
        policies_dir=policies_dir,
    )

    assert result["success"] is False
    assert result["meta"]["event"] == "incomplete_policy_profile"
    assert "reviewed enforcement posture" in result["error"]


def test_an_intact_shipped_profile_still_passes(monkeypatch, tmp_path, repo_root):
    """
    Negative control. Without this, the test above only proves the copied policy
    set was rejected for some reason, not that the downgrade is what did it.
    """
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    policies_dir = _copy_shipped_policies(repo_root, tmp_path / "intact")
    monkeypatch.delenv("AURO_POLICY_PROFILE", raising=False)
    monkeypatch.setattr(
        orchestrator,
        "generate",
        lambda *_args, **_kwargs: '{"done": true, "summary": "intact posture"}',
    )

    result = orchestrator.run(
        "tool_catalog",
        "negative control",
        policies_dir=policies_dir,
    )

    assert result["success"] is True, f"intact shipped policies were refused: {result.get('error')}"


def test_an_added_rule_does_not_cost_the_shipped_profile_check(
    monkeypatch, tmp_path, repo_root
):
    """
    An addition can only add a check, so it must not force an operator onto
    `custom`, where they would lose posture verification on the reviewed rules
    as well. Removals and edits still refuse; this is the safe direction.
    """
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    policies_dir = _copy_shipped_policies(repo_root, tmp_path / "extended")
    (policies_dir / "site_local.yaml").write_text(
        "id: site_local\n"
        "rules:\n"
        "  - id: site_local_reason_required\n"
        "    description: Local addition; every call states a reason.\n"
        "    guard: check_reason_not_empty\n"
        "    enforcement: block\n"
        "    on_error: fail_closed\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("AURO_POLICY_PROFILE", raising=False)
    monkeypatch.setattr(
        orchestrator,
        "generate",
        lambda *_args, **_kwargs: '{"done": true, "summary": "extended profile"}',
    )

    result = orchestrator.run(
        "tool_catalog",
        "probe an extended shipped profile",
        policies_dir=policies_dir,
    )

    assert result["success"] is True, f"an added rule was refused: {result.get('error')}"


def test_a_removed_rule_still_refuses_under_the_shipped_profile(
    monkeypatch, tmp_path, repo_root
):
    """
    Control for the test above, in the direction that matters: permitting
    additions must not have permitted deletions.
    """
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    policies_dir = _copy_shipped_policies(repo_root, tmp_path / "reduced")
    (policies_dir / "credential_proxy.yaml").unlink()
    monkeypatch.delenv("AURO_POLICY_PROFILE", raising=False)

    def model_must_not_run(*_args, **_kwargs):
        pytest.fail("the model ran with a shipped policy binding removed")

    monkeypatch.setattr(orchestrator, "generate", model_must_not_run)
    result = orchestrator.run(
        "tool_catalog",
        "probe a reduced shipped profile",
        policies_dir=policies_dir,
    )

    assert result["success"] is False
    assert result["meta"]["event"] == "incomplete_policy_profile"
    assert "incomplete" in result["error"]


def test_partial_shipped_policy_profile_is_refused(monkeypatch, tmp_path, repo_root):
    """One surviving rule must not masquerade as the complete shipped posture."""
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    policies_dir = tmp_path / "partial-policies"
    policies_dir.mkdir()
    (policies_dir / "credential_proxy.yaml").write_bytes(
        (repo_root / "policies" / "credential_proxy.yaml").read_bytes()
    )
    monkeypatch.delenv("AURO_POLICY_PROFILE", raising=False)

    def model_must_not_run(*_args, **_kwargs):
        pytest.fail("the model ran with a truncated shipped policy profile")

    monkeypatch.setattr(orchestrator, "generate", model_must_not_run)
    result = orchestrator.run(
        "tool_catalog",
        "probe partial policy posture",
        policies_dir=policies_dir,
    )

    assert result["success"] is False
    assert result["meta"]["event"] == "incomplete_policy_profile"
    assert "policy profile" in result["error"].lower()


def test_explicit_custom_policy_profile_is_not_compared_to_shipped_manifest(
    monkeypatch, tmp_path, repo_root
):
    """Positive control: deliberate custom policy sets remain supported."""
    from auro_runtime import orchestrator

    _audit_to_tmp(monkeypatch, tmp_path)
    policies_dir = tmp_path / "custom-policies"
    policies_dir.mkdir()
    (policies_dir / "credential_proxy.yaml").write_bytes(
        (repo_root / "policies" / "credential_proxy.yaml").read_bytes()
    )
    monkeypatch.setenv("AURO_POLICY_PROFILE", "custom")
    monkeypatch.setattr(
        orchestrator,
        "generate",
        lambda *_args, **_kwargs: '{"done": true, "summary": "custom profile"}',
    )

    result = orchestrator.run(
        "tool_catalog",
        "custom profile positive control",
        policies_dir=policies_dir,
    )

    assert result["success"] is True


def test_project_root_does_not_trust_an_arbitrary_working_directory(
    monkeypatch, tmp_path, repo_root
):
    """A CWD marker must not redirect policies, directives, or Python imports."""
    from auro_runtime.paths import get_project_root

    hostile = tmp_path / "hostile"
    (hostile / "runtime_tools").mkdir(parents=True)
    (hostile / "runtime_tools" / "__init__.py").write_text(
        "raise RuntimeError('hostile runtime_tools imported')\n",
        encoding="utf-8",
    )
    (hostile / "policies").mkdir()
    (hostile / "directives").mkdir()
    monkeypatch.chdir(hostile)
    monkeypatch.delenv("AURO_ROOT", raising=False)

    assert get_project_root().resolve() == repo_root.resolve()


def test_invalid_explicit_root_fails_instead_of_falling_back(monkeypatch, tmp_path):
    from auro_runtime.paths import get_project_root

    monkeypatch.setenv("AURO_ROOT", str(tmp_path / "incomplete-root"))
    with pytest.raises(RuntimeError, match="AURO_ROOT"):
        get_project_root()


def test_packaged_authority_assets_match_reviewed_source_sets(repo_root):
    """Positive content proof: wheel inputs cannot drift from reviewed files."""
    packaged = repo_root / "auro_runtime" / "resources"
    for name, pattern in (("directives", "*.md"), ("policies", "*.yaml")):
        source_files = {
            path.name: path.read_bytes()
            for path in (repo_root / name).glob(pattern)
        }
        packaged_files = {
            path.name: path.read_bytes()
            for path in (packaged / name).glob(pattern)
        }
        assert source_files
        assert packaged_files == source_files


def test_workspace_override_cannot_redirect_authority(monkeypatch, tmp_path, repo_root):
    from auro_runtime.paths import get_authority_root, get_workspace_root

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "directives").mkdir()
    (workspace / "policies").mkdir()
    monkeypatch.setenv("AURO_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("AURO_AUTHORITY_ROOT", raising=False)
    monkeypatch.delenv("AURO_ROOT", raising=False)

    assert get_workspace_root() == workspace.resolve()
    assert get_authority_root() == (
        repo_root / "auro_runtime" / "resources"
    ).resolve()


def test_legacy_root_cannot_redirect_authority(monkeypatch, tmp_path, repo_root):
    """AURO_ROOT may select legacy workspace state, never executable resources."""
    from auro_runtime.paths import get_authority_root

    hostile = tmp_path / "hostile-authority"
    (hostile / "directives").mkdir(parents=True)
    (hostile / "policies").mkdir()
    monkeypatch.setenv("AURO_ROOT", str(hostile))
    monkeypatch.setenv("AURO_AUTHORITY_ROOT", str(hostile))

    assert get_authority_root() == (
        repo_root / "auro_runtime" / "resources"
    ).resolve()


def test_workspace_resolution_is_frozen_for_process(monkeypatch, tmp_path):
    from auro_runtime.paths import get_workspace_root

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setenv("AURO_WORKSPACE_ROOT", str(first))

    assert get_workspace_root() == first.resolve()
    monkeypatch.setenv("AURO_WORKSPACE_ROOT", str(second))
    assert get_workspace_root() == first.resolve()

    # Positive control for test isolation: a fresh process/cache sees new config.
    get_workspace_root.cache_clear()
    assert get_workspace_root() == second.resolve()


def test_read_tools_mount_packaged_authority_not_workspace_shadow(
    monkeypatch, tmp_path
):
    from auro_runtime.paths import get_directives_dir, get_policies_dir
    from runtime_tools import file_tools

    workspace = tmp_path / "workspace"
    (workspace / "directives").mkdir(parents=True)
    (workspace / "policies").mkdir()
    (workspace / "directives" / "tool_catalog.md").write_text(
        "hostile workspace shadow", encoding="utf-8"
    )
    (workspace / "policies" / "default.yaml").write_text(
        "id: hostile", encoding="utf-8"
    )
    monkeypatch.setattr(file_tools, "_BASE_DIR", workspace.resolve())

    directive = file_tools.read_file("directives/tool_catalog.md")
    policy = file_tools.read_file("policies/default.yaml")
    assert directive["content"] == (
        get_directives_dir() / "tool_catalog.md"
    ).read_text(encoding="utf-8")
    assert policy["content"] == (
        get_policies_dir() / "default.yaml"
    ).read_text(encoding="utf-8")
    assert "hostile workspace shadow" not in directive["content"]
    assert "id: hostile" not in policy["content"]

    listed = file_tools.list_dir("policies")
    assert {entry["name"] for entry in listed["entries"]} >= {
        "default.yaml",
        "credential_proxy.yaml",
        "router.yaml",
    }


def test_authority_virtual_mount_refuses_traversal(monkeypatch, tmp_path):
    from runtime_tools import file_tools

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(file_tools, "_BASE_DIR", workspace.resolve())

    result = file_tools.read_file("directives/../policies/default.yaml")
    assert result["content"] is None
    assert "outside the allowed project directory" in result["error"]


def test_virtual_authority_mount_is_read_only(monkeypatch, tmp_path):
    from auro_runtime.paths import get_directives_dir
    from runtime_tools import file_tools

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(file_tools, "_BASE_DIR", workspace.resolve())
    authority_file = get_directives_dir() / "tool_catalog.md"
    before = authority_file.read_bytes()

    result = file_tools.write_file(
        "directives/tool_catalog.md", "attempted authority replacement"
    )

    assert result["written"] is False
    assert "protected" in result["error"].lower()
    assert authority_file.read_bytes() == before
    assert not (workspace / "directives" / "tool_catalog.md").exists()


def test_source_verifier_ignores_workspace_and_legacy_root(
    monkeypatch, tmp_path, repo_root
):
    from auro_runtime.paths import get_source_checkout_root

    fake = tmp_path / "fake"
    fake.mkdir()
    monkeypatch.setenv("AURO_WORKSPACE_ROOT", str(fake))
    monkeypatch.setenv("AURO_ROOT", str(fake))
    monkeypatch.delenv("AURO_SOURCE_ROOT", raising=False)

    assert get_source_checkout_root() == repo_root.resolve()


def test_source_verifier_rejects_incomplete_explicit_checkout(monkeypatch, tmp_path):
    from auro_runtime.paths import get_source_checkout_root

    incomplete = tmp_path / "not-a-checkout"
    incomplete.mkdir()
    monkeypatch.setenv("AURO_SOURCE_ROOT", str(incomplete))

    with pytest.raises(RuntimeError, match="complete Auro source checkout"):
        get_source_checkout_root()


def test_generic_write_treats_directives_as_intrinsically_protected(repo_root):
    """No file is created; this exercises the decision function directly."""
    from runtime_tools import file_tools

    target = repo_root / "directives" / "__p0_write_probe__.md"
    error = file_tools._is_writable_path(target, repo_root)
    assert error is not None
    assert "protected" in error.lower()


def test_env_cannot_make_protected_directives_writable(repo_root):
    """Import-time configuration must reject an attempted protected-path widening."""
    code = "import runtime_tools.file_tools"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    env["AURO_RUNTIME_WRITABLE_DIRS"] = "output,directives"
    proc = subprocess.run(
        [sys.executable, "-B", "-c", code],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode != 0
    assert "protected" in (proc.stdout + proc.stderr).lower()


def test_full_pipeline_executes_the_planned_directive_snapshot(
    monkeypatch, tmp_path
):
    """A second file read must not replace the authority checked during Plan."""
    from auro_runtime import orchestrator
    from auro_runtime.schemas import DirectiveMetadata

    _audit_to_tmp(monkeypatch, tmp_path)
    calls = []

    def alternating_load(_directory, directive_id):
        calls.append(directive_id)
        if len(calls) == 1:
            return (
                DirectiveMetadata(
                    id=directive_id,
                    description="planned",
                    tools=["list_tools"],
                    category="system",
                ),
                "planned body",
            )
        return (
            DirectiveMetadata(
                id=directive_id,
                description="swapped",
                tools=["echo"],
                category="system",
            ),
            "swapped body",
        )

    responses = iter([
        '{"tool": "echo", "args": {"message": "must be refused"}, "reason": "probe"}',
        '{"done": true, "summary": "finished"}',
    ])
    monkeypatch.setattr(orchestrator, "load_directive_by_id", alternating_load)
    monkeypatch.setattr(
        orchestrator, "generate", lambda *_args, **_kwargs: next(responses)
    )

    result = orchestrator.run("tool_catalog", "snapshot probe")

    assert len(calls) == 1
    assert result["legacy_steps"][0]["tool"] == "echo"
    assert result["legacy_steps"][0]["success"] is False
    assert "not allowed" in result["legacy_steps"][0]["error"]


def test_mcp_uses_one_explicit_exposure_set_for_list_and_run(monkeypatch, tmp_path):
    from auro_runtime import mcp_server

    _audit_to_tmp(monkeypatch, tmp_path)
    monkeypatch.setattr(
        mcp_server, "_ALLOWED_DIRECTIVE_IDS", frozenset({"tool_catalog"}), raising=False
    )
    visible = mcp_server.list_directives()
    assert [item["id"] for item in visible] == ["tool_catalog"]

    calls = []

    def fake_run(directive_id, request, **kwargs):
        calls.append((directive_id, request, kwargs))
        return {
            "success": True,
            "messages": [],
            "final_summary": "ok",
            "error": None,
            "meta": {},
            "legacy_steps": [],
        }

    monkeypatch.setattr(mcp_server, "orchestrator_run", fake_run)
    allowed = asyncio.run(mcp_server.run_directive("tool_catalog", "allowed"))
    assert allowed["success"] is True
    assert calls[0][2]["allowed_directive_ids"] == {"tool_catalog"}

    refused = asyncio.run(mcp_server.run_directive("health_check", "refused"))
    assert refused["success"] is False
    assert refused["meta"]["event"] == "directive_not_exposed"
    assert len(calls) == 1


def test_mcp_empty_exposure_set_lists_and_runs_nothing(monkeypatch, tmp_path):
    from auro_runtime import mcp_server

    _audit_to_tmp(monkeypatch, tmp_path)
    monkeypatch.setattr(
        mcp_server, "_ALLOWED_DIRECTIVE_IDS", frozenset(), raising=False
    )
    assert mcp_server.list_directives() == []
    result = asyncio.run(mcp_server.run_directive("tool_catalog", "refused"))
    assert result["success"] is False
    assert result["meta"]["event"] == "directive_not_exposed"


def test_mcp_startup_requires_the_dedicated_workspace_setting(
    monkeypatch, tmp_path
):
    """A legacy/local workspace is not sufficient authority for an MCP server."""
    from auro_runtime import mcp_server
    from auro_runtime.paths import get_workspace_root

    legacy = tmp_path / "legacy-workspace"
    legacy.mkdir()
    monkeypatch.delenv("AURO_WORKSPACE_ROOT", raising=False)
    monkeypatch.setenv("AURO_ROOT", str(legacy))
    get_workspace_root.cache_clear()

    with pytest.raises(RuntimeError, match="AURO_WORKSPACE_ROOT must name"):
        mcp_server.require_explicit_workspace()

    # Positive control: the dedicated setting resolves to the exact frozen root.
    monkeypatch.setenv("AURO_WORKSPACE_ROOT", str(legacy))
    get_workspace_root.cache_clear()
    assert mcp_server.require_explicit_workspace() == legacy.resolve()
    assert mcp_server.create_stdio_server() is mcp_server._stdio_server


def test_authenticated_mcp_server_uses_the_configured_public_url(
    monkeypatch, tmp_path
):
    from auro_runtime import mcp_server
    from auro_runtime.paths import get_workspace_root

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("AURO_WORKSPACE_ROOT", str(workspace))
    get_workspace_root.cache_clear()

    server = mcp_server.create_authenticated_server(
        "https://runtime.example.test/auro/"
    )

    assert str(server.settings.auth.issuer_url).rstrip("/") == (
        "https://runtime.example.test/auro"
    )
    assert str(server.settings.auth.resource_server_url).rstrip("/") == (
        "https://runtime.example.test/auro"
    )


def test_mcp_server_factories_refuse_without_explicit_workspace(monkeypatch):
    from auro_runtime import mcp_server
    from auro_runtime.paths import get_workspace_root

    monkeypatch.delenv("AURO_WORKSPACE_ROOT", raising=False)
    monkeypatch.delenv("AURO_ROOT", raising=False)
    get_workspace_root.cache_clear()

    with pytest.raises(RuntimeError, match="AURO_WORKSPACE_ROOT must name"):
        mcp_server.create_stdio_server()
    with pytest.raises(RuntimeError, match="AURO_WORKSPACE_ROOT must name"):
        mcp_server.create_authenticated_server("https://runtime.example.test")


def test_cli_mcp_refuses_before_transport_without_explicit_workspace(repo_root):
    """Exercise the real CLI boundary; a unit-only helper assertion is insufficient."""
    env = os.environ.copy()
    env.pop("AURO_WORKSPACE_ROOT", None)
    env.pop("AURO_ROOT", None)
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "auro_runtime", "mcp"],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert proc.returncode == 2
    assert "AURO_WORKSPACE_ROOT must name" in proc.stderr


def test_cli_remote_mcp_requires_public_url_for_non_loopback_host(
    tmp_path, repo_root
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    env = os.environ.copy()
    env["AURO_WORKSPACE_ROOT"] = str(workspace)
    env["AURO_MCP_API_KEY"] = "test-only-placeholder"
    proc = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "auro_runtime",
            "mcp",
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert proc.returncode == 2
    assert "--public-url is required" in proc.stderr


def test_static_verifier_accepts_the_current_source_tree():
    """The release gate itself must run cleanly, not just its pytest subprocess."""
    from runtime_tools.verify_tools import verify_code_static

    result = verify_code_static()

    assert result["passed"] is True, result["findings"]
    syntax_check = next(
        check for check in result["checks"] if check["name"] == "syntax_check"
    )
    assert syntax_check["passed"] is True
    assert syntax_check["detail"] != []


def test_static_verifier_rejects_a_utf8_bom_with_a_named_diagnostic(
    monkeypatch, tmp_path
):
    """The encoding contract is enforced on a hostile tree, not inferred."""
    from runtime_tools import verify_tools

    for dirname in ("auro_runtime", "runtime_tools", "directives", "policies"):
        (tmp_path / dirname).mkdir()
    (tmp_path / "runtime_tools" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "auro_runtime" / "bom_probe.py").write_bytes(
        b"\xef\xbb\xbfVALUE = 1\n"
    )
    monkeypatch.setattr(verify_tools, "_PROJECT_ROOT", tmp_path)

    result = verify_tools.verify_code_static()

    assert result["passed"] is False
    assert any(
        finding["code"] == "SOURCE_BOM"
        and finding["file"] == "auro_runtime/bom_probe.py"
        for finding in result["findings"]
    )


@pytest.mark.parametrize(
    "verifier_name",
    (
        "verify_code_static",
        "verify_code_dynamic",
        "verify_security",
        "verify_output",
    ),
)
def test_installed_verifiers_return_source_checkout_required(
    monkeypatch, verifier_name
):
    """An installed wheel must refuse as data instead of leaking an exception."""
    from runtime_tools import verify_tools

    monkeypatch.setattr(verify_tools, "_PROJECT_ROOT", None)
    monkeypatch.setattr(
        verify_tools,
        "get_source_checkout_root",
        lambda: (_ for _ in ()).throw(
            RuntimeError(
                "No complete Auro source checkout is available; "
                "set AURO_SOURCE_ROOT to one."
            )
        ),
    )

    result = getattr(verify_tools, verifier_name)()

    assert result["passed"] is False
    assert result["error_count"] == 1
    assert result["checks"] == [{
        "name": "source_checkout",
        "passed": False,
        "detail": (
            "No complete Auro source checkout is available; "
            "set AURO_SOURCE_ROOT to one."
        ),
    }]
    assert result["findings"][0]["code"] == "SOURCE_CHECKOUT_REQUIRED"


def test_secret_scan_covers_release_manifest_and_ci_workflows(
    monkeypatch, tmp_path
):
    """The whole-tree claim includes publication files outside Python packages."""
    from runtime_tools import verify_tools

    for dirname in verify_tools._SOURCE_DIRS:
        (tmp_path / dirname).mkdir(parents=True)
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    secret_assignment = "api" + '_key = "' + ("q" * 24) + '"\n'
    (tmp_path / "MANIFEST.in").write_text(secret_assignment, encoding="utf-8")
    (workflow_dir / "ci.yml").write_text(secret_assignment, encoding="utf-8")
    monkeypatch.setattr(verify_tools, "_PROJECT_ROOT", tmp_path)

    result = verify_tools.verify_security()

    detected_files = {
        finding["file"].replace("\\", "/")
        for finding in result["findings"]
        if finding["code"] == "SECRET_DETECTED"
    }
    assert {"MANIFEST.in", ".github/workflows/ci.yml"} <= detected_files
