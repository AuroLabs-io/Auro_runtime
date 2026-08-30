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

import subprocess
from unittest.mock import patch

import pytest

import auro_runtime.executor as executor_mod
import auro_runtime.policy as policy_mod
from auro_runtime.paths import get_policies_dir
import runtime_tools.verify_tools as vt


def _root_has_source_control() -> bool:
    try:
        return (vt._root() / ".git").exists()
    except Exception:
        return False


# Two different environments, two different skips, and keeping them apart is the
# point. The verifier's own sandbox is a copy of the tracked tree WITHOUT `.git`
# -- deliberately, so `git status` inside it cannot report on the real checkout
# -- and the dynamic phase runs this suite in there. So a test that builds a
# sandbox over `_root()` cannot run inside one, and a test that calls
# `verify_code_dynamic` expecting it to do work cannot run where the recursion
# guard short-circuits it. Both are skips, not failures: the environment cannot
# express the question. Everything that constructs its own repository in tmp_path
# runs everywhere, which is what keeps the derivation itself proved in both.
requires_source_control = pytest.mark.skipif(
    not _root_has_source_control(),
    reason=(
        "the sandbox copy is derived from `git ls-files`; this tree has no .git "
        "(the verifier's own sandbox is the ordinary case)"
    ),
)

requires_a_reachable_dynamic_phase = pytest.mark.skipif(
    vt._inside_named_sandbox(),
    reason="the recursion guard returns before the dynamic phase does any work",
)


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
    if not _root_has_source_control():
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
        policy_mod.load_policies(get_policies_dir())
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

    Note what this test must not depend on. `classify_text` is called once per
    line of `git status` output, so patching it to raise proves nothing when the
    working tree happens to be clean -- the loop body never runs and the check
    passes for an unrelated reason. An earlier version of this test did exactly
    that and passed only because the tree was dirty while it was written. Supply
    the porcelain output so the crash is reached whatever the checkout looks
    like.
    """
    import subprocess

    staged = subprocess.CompletedProcess(
        ["git", "status", "--porcelain"], 0, "M  auro_runtime/probe.py\n", ""
    )
    with patch.object(vt.subprocess, "run", lambda *a, **k: staged):
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


# --- The recursion guard must not be reachable from the environment -------
#
# `verify_code_dynamic` returns early, reporting a passing `recursion_guard`
# check and running nothing, when it believes it is already inside a
# verification sandbox. That belief used to rest on a bare "1" in
# AURO_VERIFY_SANDBOX, which anyone could export -- a vacuous pass reachable
# from the environment and named in no shipped document. The marker now
# carries the sandbox root and the reader checks containment, so the two
# cases are distinguishable. These tests drive both directions: the guard
# must still fire where it is correct, and must not fire where it is not.


def _sandbox_root_containing_verify_tools():
    """The directory a genuine sandbox would name: an ancestor of the module."""
    from pathlib import Path

    return str(Path(vt.__file__).resolve().parent.parent)


def test_an_unset_marker_does_not_trip_the_recursion_guard(monkeypatch):
    monkeypatch.delenv(vt._SANDBOX_MARKER, raising=False)
    assert vt._inside_named_sandbox() is False


def test_a_marker_naming_the_loaded_tree_trips_the_recursion_guard(monkeypatch):
    """The legitimate case. Breaking this would let sandboxes nest."""
    monkeypatch.setenv(vt._SANDBOX_MARKER, _sandbox_root_containing_verify_tools())
    assert vt._inside_named_sandbox() is True


@pytest.mark.parametrize("value", ["1", "true", "", "/nonexistent/sandbox"])
def test_an_ambient_marker_does_not_trip_the_recursion_guard(monkeypatch, value):
    """
    The defect. Each of these was previously indistinguishable from a real
    re-entry, and each suppressed the entire dynamic phase.
    """
    monkeypatch.setenv(vt._SANDBOX_MARKER, value)
    assert vt._inside_named_sandbox() is False


def test_a_marker_naming_an_unrelated_real_directory_is_ignored(monkeypatch, tmp_path):
    """A directory that exists but does not contain the running module."""
    monkeypatch.setenv(vt._SANDBOX_MARKER, str(tmp_path))
    assert vt._inside_named_sandbox() is False


@requires_source_control
def test_the_sandbox_marker_carries_a_root_that_satisfies_the_reader():
    """
    Binds the writer to the reader. `_Sandbox.env()` and
    `_inside_named_sandbox` are the two halves of one control, and a test that
    only checked the reader would stay green if the writer went back to "1".
    """
    with vt._Sandbox() as sandbox:
        env = vt._Sandbox()
        env._path = sandbox
        marker = env.env()[vt._SANDBOX_MARKER]

    assert marker == str(sandbox)
    assert marker not in ("1", "true")


@requires_source_control
def test_an_ambient_marker_leaves_the_dynamic_phase_reachable(monkeypatch):
    """
    The read site must branch on containment, not on the raw variable. Proven
    by reachability rather than by inspection: with the marker set ambiently,
    execution must get past the guard and reach the sandbox it would have
    skipped.
    """
    monkeypatch.setenv(vt._SANDBOX_MARKER, "1")

    class _Reached(Exception):
        pass

    class _ExplodingSandbox:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            raise _Reached()

        def __exit__(self, *exc):
            return False

    with patch.object(vt, "_Sandbox", _ExplodingSandbox):
        with pytest.raises(_Reached):
            vt.verify_code_dynamic()


# ---------------------------------------------------------------------------
# The sandbox manifest
#
# The copy the dynamic phase runs in was a hand-kept list of directories plus a
# hand-kept list of root files, and it was short four times: tests/, docs/,
# .github/, and finally publish_release.py, whose absence surfaced as a
# collection error in a phase nothing in CI ran. Every one of those was found by
# a person running the verifier by hand and reading the traceback.
#
# The list is now derived from `git ls-files`, so these tests are about the
# derivation rather than about any particular file: one proves a tracked file
# no list would name arrives in the copy, and the others prove that a manifest
# which cannot be derived refuses instead of copying less. The second direction
# is the one that matters -- a fallback to a partial list would restore the
# defect exactly, and it would present as a pass.
# ---------------------------------------------------------------------------


def _staged_repo(tmp_path):
    """A real repository holding a tracked file, and an untracked one beside it.

    Staged rather than committed: `git ls-files` reads the index, so this needs
    no user identity configured and cannot fail on a machine without one.
    """
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "module.py").write_text("value = 1\n", encoding="utf-8")
    (root / "unlisted_root_file.py").write_text("value = 2\n", encoding="utf-8")
    (root / "untracked.py").write_text("value = 3\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "add", "pkg/module.py", "unlisted_root_file.py"],
        cwd=root, check=True, capture_output=True,
    )
    return root


def test_the_sandbox_copies_what_git_tracks_not_what_a_list_names(tmp_path):
    """The derivation, on a tree no inventory in this file has ever seen.

    `unlisted_root_file.py` is the whole point: it is in the copy because it is
    tracked, and no list mentions it. The untracked file's absence is the same
    claim from the other side -- the copy is the repository, not the directory.
    """
    root = _staged_repo(tmp_path)
    with patch.object(vt, "_root", lambda: root):
        with vt._Sandbox() as sandbox:
            assert (sandbox / "pkg" / "module.py").is_file()
            assert (sandbox / "unlisted_root_file.py").is_file()
            assert not (sandbox / "untracked.py").exists()


@requires_source_control
def test_the_copy_holds_every_tracked_root_python_module():
    """The instance that started this, generalised to its class.

    Asserting `publish_release.py` by name would pass again the day a sixth root
    module is added and forgotten. Asserting the set means the next one is
    carried by the same fact that carries this one.
    """
    tracked = vt._tracked_paths(vt._root())
    root_modules = [
        name for name in tracked if name.endswith(".py") and "/" not in name
    ]
    assert "publish_release.py" in root_modules, (
        "the tracked file whose omission from the old list hid behind a green suite"
    )

    with vt._Sandbox() as sandbox:
        absent = [name for name in root_modules if not (sandbox / name).is_file()]
    assert absent == []


@requires_a_reachable_dynamic_phase
def test_a_tree_without_source_control_refuses_instead_of_copying_less(tmp_path):
    """Fail closed: no manifest, no run, and the report says which.

    The tempting alternative is falling back to the old lists when git is
    unavailable. That would run the suite over a copy nobody can characterise
    and report the result as a pass, which is the defect this replaces.

    The directory is stocked with exactly the files such a fallback would name,
    which is the difference between this test and the one it replaced. An empty
    directory catches a fallback only by accident -- the copy then fails for
    lacking files rather than for being underived, and a fallback that happens
    to name files that exist would sail through. Here a fallback gets a copy it
    can build, and is caught by `test_suite` appearing at all.
    """
    plain = tmp_path / "no-git"
    (plain / "auro_runtime").mkdir(parents=True)
    (plain / "auro_runtime" / "__init__.py").write_text("", encoding="utf-8")
    (plain / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    (plain / "README.md").write_text("# x\n", encoding="utf-8")
    with patch.object(vt, "_root", lambda: plain):
        result = vt.verify_code_dynamic()

    assert result["passed"] is False
    assert any(
        finding["code"] == "SANDBOX_MANIFEST_UNAVAILABLE"
        for finding in result["findings"]
    )
    assert "test_suite" not in [check["name"] for check in result["checks"]], (
        "nothing may be reported as executed when the copy was never made"
    )


@requires_a_reachable_dynamic_phase
def test_a_tracked_file_missing_from_disk_refuses(tmp_path):
    """The substrate must be faithful, and a partial copy is not the checkout.

    A tracked file deleted but not committed makes the copy differ from both
    HEAD and the working tree. Copying the rest and running the suite over it
    would report on a tree that exists nowhere.
    """
    root = _staged_repo(tmp_path)
    (root / "pkg" / "module.py").unlink()
    with patch.object(vt, "_root", lambda: root):
        result = vt.verify_code_dynamic()

    assert result["passed"] is False
    assert any(
        finding["code"] == "SANDBOX_MANIFEST_UNAVAILABLE"
        for finding in result["findings"]
    )
    assert "module.py" in _check(result, "sandbox_manifest")["detail"]


def test_the_sandbox_itself_refuses_a_manifest_it_cannot_honour(tmp_path):
    """The same refusal, driven at `_Sandbox` rather than through the caller.

    `verify_code_dynamic` pre-checks the manifest before constructing the box,
    so the test above never reaches the box's own guard -- deleting that guard
    entirely left the whole suite green. Two enforcement points behind one
    observable are one control to any test that cannot tell them apart, and the
    box's guard is the one that still matters when a file disappears between
    the pre-check and the copy.
    """
    root = _staged_repo(tmp_path)
    (root / "pkg" / "module.py").unlink()
    with patch.object(vt, "_root", lambda: root):
        with pytest.raises(vt._SandboxManifestError, match="not present"):
            with vt._Sandbox():
                pass


@requires_a_reachable_dynamic_phase
def test_a_copy_failure_is_a_recorded_refusal_not_an_exception(tmp_path):
    """A locked file is ordinary on Windows; an escaping exception is not a report.

    The refusal path wrapped only the enumeration, so anything raised during
    the copy -- `PermissionError`, a full temp volume -- propagated out of
    `verify_code_dynamic` and out of `verify_output`, handing an in-process
    caller an exception where the contract promises a structured verdict. The
    comment above that block claimed the opposite.
    """
    root = _staged_repo(tmp_path)

    def locked(src, dst, *args, **kwargs):
        raise PermissionError(13, "file locked by another process")

    with patch.object(vt, "_root", lambda: root), \
            patch.object(vt.shutil, "copy2", locked):
        result = vt.verify_code_dynamic()

    assert result["passed"] is False
    assert any(
        finding["code"] == "SANDBOX_MANIFEST_UNAVAILABLE"
        for finding in result["findings"]
    )
    assert "file locked" in _check(result, "sandbox_manifest")["detail"]


@requires_a_reachable_dynamic_phase
def test_a_sandbox_run_that_passed_nothing_cannot_report_a_pass(tmp_path):
    """pytest exits 0 when every test skips, and a CI job now consumes this check.

    The dynamic phase read only the exit code, so "everything skipped" was
    recorded as `test_suite: passed`. That is the same vacuity this file's
    header states as a rule and applies to `secret_scan` and
    `guard_completeness` -- a count, not a boolean.

    Runs against its own repository rather than the ambient one. The first
    version used the real root and passed here while failing inside the release
    gate's `git archive` export, which has no `.git`: the manifest refused
    first, so `test_suite` never appeared and the assertion was reading a
    result from a different code path. Skipping there would have been the
    lesser fix -- the question is expressible anywhere, it just needs a tree of
    its own.
    """
    from types import SimpleNamespace

    root = _staged_repo(tmp_path)
    real_run = vt.subprocess.run

    def fake_run(cmd, *args, **kwargs):
        if cmd[:1] == ["git"]:
            return real_run(cmd, *args, **kwargs)
        if "pytest" in cmd:
            return SimpleNamespace(returncode=0, stdout="2 skipped in 0.01s", stderr="")
        return SimpleNamespace(returncode=0, stdout="OK\n", stderr="")

    with patch.object(vt, "_root", lambda: root), \
            patch.object(vt.subprocess, "run", fake_run):
        result = vt.verify_code_dynamic()

    assert result["passed"] is False
    assert "test_suite" in _failed_checks(result)
    assert any(finding["code"] == "NO_TESTS_PASSED" for finding in result["findings"])


@requires_source_control
def test_the_secret_scan_opens_every_file_that_ships():
    """The sibling inventory, and the one this session edited by hand.

    `_iter_scannable_files` walked `_SCAN_DIRS` plus a hand-written tuple of
    nine root filenames. Adding `publish_release.py` to that tuple -- in the
    same commit that replaced the sandbox's hand-kept lists -- left it two
    files short: `SECURITY.md` and `.gitattributes` were tracked, shipped, and
    never opened, so a credential committed to SECURITY.md passed
    `verify_security()` clean.

    Asserting the tracked set rather than those two names, because naming them
    would pass again the moment a tenth root file is added and forgotten.
    """
    scanned = {path.resolve() for path in vt._iter_scannable_files()}
    tracked = {(vt._root() / name).resolve() for name in vt._tracked_paths(vt._root())}

    missed = sorted(str(path) for path in tracked - scanned)
    assert missed == [], f"tracked files the secret scan never opens: {missed}"


# The scan has two halves and they overlap on almost every file in this
# repository, so the assertion above passes with either one deleted -- the same
# two-controls-one-observable shape that hid a symlink guard and a manifest
# guard earlier in this work. What each half uniquely reaches is what each of
# the next two tests pins.


def test_the_scan_sees_an_untracked_file_in_the_root(tmp_path):
    """What the directory walk reaches and the tracked floor cannot.

    An uncommitted `.env` beside `pyproject.toml` is the case a secret scan
    most obviously exists for, and it is invisible to anything derived from
    `git ls-files`.
    """
    root = _staged_repo(tmp_path)
    (root / ".env").write_text("TOKEN=not-committed\n", encoding="utf-8")

    with patch.object(vt, "_root", lambda: root):
        scanned = {path.name for path in vt._iter_scannable_files()}

    assert ".env" in scanned, (
        "an untracked root file is invisible to the tracked floor; the "
        "directory walk is what reaches it"
    )


def test_the_scan_sees_a_tracked_file_no_walk_would_reach(tmp_path):
    """What the tracked floor reaches and the walks cannot.

    A tracked file in a directory that is neither the root nor one of
    `_SCAN_DIRS`. Adding its directory to `_SCAN_DIRS` by hand is precisely the
    move this whole change is replacing.
    """
    root = _staged_repo(tmp_path)
    outside = root / "packaging" / "notes.md"
    outside.parent.mkdir()
    outside.write_text("nothing secret here\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "packaging/notes.md"],
        cwd=root, check=True, capture_output=True,
    )

    with patch.object(vt, "_root", lambda: root):
        scanned = {
            str(path.relative_to(root)).replace("\\", "/")
            for path in vt._iter_scannable_files()
        }

    assert "packaging/notes.md" in scanned, (
        "neither the root listing nor _SCAN_DIRS reaches this; the tracked "
        "floor is what does"
    )
