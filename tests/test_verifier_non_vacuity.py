"""
The verifier is subject to the laws it enforces.

`verify_security()` reports a headline `passed` alongside the `checks` list it
derived that verdict from. Those two used to be assembled independently, so the
object could -- and did -- contradict itself: a subcheck that examined nothing or
crashed outright recorded `passed: False` while the top-level result stayed
`passed: True`. A caller reading the verdict and a caller reading the checks got
opposite answers from the same return value.

Two kinds of assertion here, and the distinction is the point:

* **Numeric evidence.** The passing path must report a non-zero count of what it
  examined. "Scanned clean" over zero files is not a clean result, and a boolean
  assertion cannot tell the two apart.
* **Negative fixtures.** Each evidence source is driven to zero or to failure in
  turn, and the aggregate must not stay green. A control is only proven by the
  input that should break it.
"""

from unittest.mock import patch

import pytest

import auro_runtime.executor as executor_mod
import auro_runtime.policy as policy_mod
import runtime_tools.verify_tools as vt


@pytest.fixture(scope="module")
def baseline():
    """The real verifier over the real tree."""
    return vt.verify_security()


def _check(result: dict, name: str) -> dict:
    return next(c for c in result["checks"] if c["name"] == name)


def _failed_checks(result: dict) -> list[str]:
    return [c["name"] for c in result["checks"] if not c["passed"]]


# --- Numeric evidence: the passing path must say how much it examined ------


def test_the_tree_verifies_clean(baseline):
    """
    The anchor. Every negative fixture below is measured against this.

    `verify_code_dynamic` runs this suite inside a sandbox that copies the source
    directories but not `.git`, so `git status` cannot run there and the
    staged-file check correctly reports that it verified nothing. That is the
    right answer for a tree with no source control, not a failure of this test —
    but skipping the case would leave nothing asserted in the environment the
    release gate actually runs, so assert the expected shape instead.
    """
    if not (vt._root() / ".git").is_dir():
        assert _failed_checks(baseline) == ["sensitive_files"], (
            "with no .git present, sensitive_files is the only check that "
            f"should fail: {_failed_checks(baseline)}"
        )
        return

    assert baseline["passed"] is True
    assert _failed_checks(baseline) == []


def test_the_secret_scan_reports_a_non_zero_file_count(baseline):
    """
    A count, not a boolean.

    The scan used to be driven by `git diff --name-only HEAD`, which covers
    nothing on a clean tree, outside a repo, or in a fresh clone -- and then
    reported that as a pass. Asserting the verdict alone cannot distinguish
    "scanned everything, found nothing" from "scanned nothing".
    """
    detail = _check(baseline, "secret_scan")["detail"]
    scanned = int(str(detail).split()[0])

    assert scanned > 0, f"secret scan examined no files: {detail!r}"


def test_guard_completeness_reports_non_zero_rules_and_guards(baseline):
    detail = str(_check(baseline, "guard_completeness")["detail"])

    assert "0 enforceable rules" not in detail
    assert policy_mod.get_enforceable_rules(
        policy_mod.load_policies(vt._root() / "policies")
    ), "no enforceable rules loaded"


def test_tool_schema_coverage_examined_a_non_empty_registry(baseline):
    assert executor_mod.get_registry(), "tool registry is empty"
    assert "All" in str(_check(baseline, "tool_schemas")["detail"])


# --- Negative fixtures: drive each evidence source to nothing --------------


def test_a_secret_scan_over_zero_files_cannot_report_a_pass():
    """
    The instance this whole file exists for.

    Note the error count: zero. The empty scan raises a *warning*, and the old
    aggregate was `error_count == 0`, so this state produced a top-level pass
    with `secret_scan: passed=False` sitting inside it. Promoting the severity
    would have closed this one case; deriving the verdict from the checks closes
    the shape.
    """
    with patch.object(vt, "_iter_scannable_files", lambda: iter([])):
        result = vt.verify_security()

    assert result["passed"] is False
    assert "secret_scan" in _failed_checks(result)


def test_zero_enforceable_rules_cannot_report_a_pass():
    """"0 enforceable rules, all guards present" was literally true and useless."""
    with patch.object(policy_mod, "get_enforceable_rules", lambda policies: []):
        result = vt.verify_security()

    assert result["passed"] is False
    assert "guard_completeness" in _failed_checks(result)


def test_an_empty_tool_registry_cannot_report_a_pass():
    with patch.object(executor_mod, "get_registry", lambda: {}):
        result = vt.verify_security()

    assert result["passed"] is False
    assert "tool_schemas" in _failed_checks(result)


def test_a_tool_without_a_schema_cannot_report_a_pass():
    """
    Both branches of this check used to hardcode `passed: True`, so its only
    False came from its own except handler -- it reported failure when it
    crashed and never when the condition it examines was violated. Nothing in
    the tree triggers it today, which made it a trap for whoever registered the
    next schema-less tool rather than a live false pass.
    """
    registry = dict(executor_mod.get_registry())
    name = next(iter(registry))
    fn, doc, _ = registry[name]
    registry[name] = (fn, doc, None)

    with patch.object(executor_mod, "get_registry", lambda: registry):
        result = vt.verify_security()

    assert result["passed"] is False
    assert "tool_schemas" in _failed_checks(result)


def test_a_registered_guard_bound_by_no_rule_cannot_report_a_pass():
    """
    The reverse direction. The check proved every rule names a guard that
    exists, and called that completeness -- a guard registered but bound by no
    rule reads as protection on review and never runs.
    """
    import auro_runtime.guards as guards_mod

    inflated = dict(guards_mod.get_guard_registry())
    inflated["check_nothing_binds_this"] = lambda ctx: None

    with patch.object(guards_mod, "get_guard_registry", lambda: inflated):
        result = vt.verify_security()

    assert result["passed"] is False
    assert "guard_completeness" in _failed_checks(result)


def test_a_failed_source_control_query_cannot_report_a_pass():
    """
    The original card's headline defect, still live until now: git exits 128 and
    prints nothing to stdout when the tree is not a repository, so the staged-file
    loop found no lines and the check reported "No sensitive files staged".

    An inspection that failed and an inspection that found nothing were
    indistinguishable in the output, and only one of them is a clean result.
    """
    import subprocess

    failed_git = subprocess.CompletedProcess(
        ["git", "status", "--porcelain"], 128, "", "fatal: not a git repository"
    )
    with patch.object(vt.subprocess, "run", lambda *a, **k: failed_git):
        result = vt.verify_security()

    assert result["passed"] is False
    assert "sensitive_files" in _failed_checks(result)
    assert "git status failed" in _check(result, "sensitive_files")["detail"]


def test_a_subcheck_that_crashes_cannot_report_a_pass():
    """
    A control that reports on a subsystem must not depend on that subsystem
    being healthy to run.

    Every `except` handler recorded `passed: False` in its check and raised no
    finding, so a crashed subcheck contributed nothing to the error count and
    the aggregate stayed green. Error count here is zero for exactly that
    reason, which is why the verdict has to come from the checks.
    """
    with patch.object(vt, "classify_text", side_effect=RuntimeError("boom")):
        result = vt.verify_security()

    assert result["passed"] is False
    assert "sensitive_files" in _failed_checks(result)


# --- The orchestrator inherits the rule ------------------------------------


def test_verify_output_does_not_pass_over_a_failed_static_phase():
    """
    Same defect one level up. `verify_output` gated the dynamic phase on the
    accumulated *error count*, so a static phase that reported failure without
    raising an error finding let the dynamic phase run on top of it -- and a
    skipped phase is not a passed one.
    """
    with patch.object(vt, "_iter_scannable_files", lambda: iter([])):
        result = vt.verify_output()

    assert result["passed"] is False
    security = next(p for p in result["phases"] if p["phase"] == "security")
    assert security["passed"] is False

    dynamic = next((p for p in result["phases"] if p["phase"] == "code_dynamic"), None)
    assert dynamic is not None
    assert dynamic["passed"] is False
    assert dynamic.get("skipped") is True
