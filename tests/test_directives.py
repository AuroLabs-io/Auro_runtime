"""
Shipped directive integrity.

Directives are content, not code, so nothing else in the suite catches a
directive that names a tool which no longer exists. That is the same failure
class as the stale policy tool name which once made the runtime unable to run
anything: it parses fine, ships fine, and fails at execution time.
"""

import pytest

from auro_runtime.directive import (
    DIRECTIVE_ID_RE,
    allowed_tools_for,
    list_directives,
    load_directive,
    load_directive_by_id,
)
from auro_runtime.schemas import DirectiveCategory, DirectiveMetadata

VALID_CATEGORIES = set(DirectiveCategory.__args__)


class TestEmptyToolScopeFailsClosed:
    """
    An empty or undeclared `tools:` must grant NO tools.

    Before this was fixed, all three orchestrator call sites read
    `set(meta.tools) if meta.tools else set(get_registry().keys())`, and the
    parser defaults a missing key to an empty list. So an omitted -- or
    misspelled -- front-matter key granted the entire tool registry, silently,
    while passing validation. Empty scope meant maximum privilege.

    That inverts the fail-safe reading used elsewhere: treating an unset scope
    as "everything" is safe for a scanner, where breadth means more coverage,
    and unsafe for a privilege grant, where breadth means more access.
    """

    def test_empty_tools_list_grants_no_tools(self):
        meta = DirectiveMetadata(id="probe", description="", tools=[], category="task")
        assert allowed_tools_for(meta) == set()

    def test_declared_tools_are_granted_exactly(self):
        meta = DirectiveMetadata(id="probe", description="", tools=["read_file"], category="task")
        assert allowed_tools_for(meta) == {"read_file"}

    @pytest.mark.parametrize(
        ("front_matter", "case"),
        [
            ("id: probe\ndescription: no tools key at all\n", "key omitted"),
            ("id: probe\ndescription: explicitly empty\ntools: []\n", "explicitly empty"),
            ("id: probe\ndescription: misspelled key\ntool: [read_file, write_file]\n", "misspelled key"),
        ],
    )
    def test_directive_without_usable_tools_key_grants_nothing(self, tmp_path, front_matter, case):
        path = tmp_path / "probe.md"
        path.write_text(f"---\n{front_matter}---\n\nBody.\n", encoding="utf-8")
        meta, _ = load_directive(path)
        assert allowed_tools_for(meta) == set(), f"{case} must not widen scope"

    def test_no_orchestrator_call_site_expands_an_empty_scope(self, repo_root):
        """
        The idiom was duplicated at three call sites, so a fix applied to one
        would be invisible in the other two. This pins all of them.
        """
        src = (repo_root / "auro_runtime" / "orchestrator.py").read_text(encoding="utf-8")
        assert "if meta.tools else" not in src, (
            "an orchestrator call site still expands an empty tool scope to the full registry"
        )
        assert src.count("allowed_tools_for(meta)") == 3, (
            "expected all three allowed_tools call sites to route through allowed_tools_for()"
        )


@pytest.fixture(scope="module")
def directives_dir(repo_root):
    return repo_root / "directives"


@pytest.fixture(scope="module")
def directive_files(directives_dir):
    files = sorted(directives_dir.glob("*.md"))
    assert files, "no directives found — the shipped directive set should not be empty"
    return files


@pytest.fixture(scope="module")
def loaded_directives(directives_dir, directive_files):
    return [load_directive_by_id(directives_dir, p.stem) for p in directive_files]


def test_every_directive_loads(directives_dir, directive_files):
    """A directive that cannot be parsed is unusable, and nothing else would notice."""
    for path in directive_files:
        meta, body = load_directive_by_id(directives_dir, path.stem)
        assert meta.id, f"{path.name} has no id"
        assert body.strip(), f"{path.name} has an empty body"


def test_directive_id_matches_filename(directives_dir, directive_files):
    """load_directive_by_id resolves by filename, so a mismatch makes the id a lie."""
    for path in directive_files:
        meta, _ = load_directive_by_id(directives_dir, path.stem)
        assert meta.id == path.stem, f"{path.name} declares id '{meta.id}'"


def test_directive_ids_are_traversal_safe(loaded_directives):
    for meta, _ in loaded_directives:
        assert DIRECTIVE_ID_RE.match(meta.id), f"id '{meta.id}' would be rejected as unsafe"


def test_every_directive_has_a_description(loaded_directives):
    """The description is what the router sees; an empty one makes the directive unroutable."""
    for meta, _ in loaded_directives:
        assert meta.description.strip(), f"{meta.id} has no description"


def test_every_directive_category_is_valid(loaded_directives):
    for meta, _ in loaded_directives:
        assert meta.category in VALID_CATEGORIES, f"{meta.id} has category '{meta.category}'"


def test_every_declared_tool_is_registered(loaded_directives, registry):
    """
    The regression test for this file's whole reason to exist. A directive naming
    a tool that no longer exists fails only when someone runs it.
    """
    for meta, _ in loaded_directives:
        for tool in meta.tools:
            assert tool in registry, (
                f"directive '{meta.id}' declares tool '{tool}', which is not registered. "
                f"Registered: {sorted(registry)}"
            )


def test_no_directive_references_pre_rename_paths(loaded_directives):
    """
    The carve renamed auro/ -> auro_runtime/ and tools/ -> runtime_tools/. Stale
    prose paths survived two separate cleanup passes because they sat outside the
    line ranges anyone was looking at.
    """
    for meta, body in loaded_directives:
        assert "`auro/`" not in body, f"directive '{meta.id}' references pre-rename `auro/`"
        assert "`tools/`" not in body, f"directive '{meta.id}' references pre-rename `tools/`"
        assert "auro_web_" not in body, f"directive '{meta.id}' references the removed auro_web_ prefix"


def test_list_directives_returns_every_file(directives_dir, directive_files):
    listed = list_directives(directives_dir)
    assert len(listed) == len(directive_files)


def test_validate_directive_passes_for_every_shipped_directive(directive_files, registry):
    """Run the project's own validator over its own content."""
    from runtime_tools.validate_directive_tools import validate_directive

    for path in directive_files:
        result = validate_directive(f"directives/{path.name}")
        assert result.get("valid") is True, f"{path.name}: {result.get('errors')}"


# --- The verification directives specifically ---------------------------------


def test_verify_project_covers_the_whole_gate(directives_dir, registry):
    """verify_project exists to exercise the verify_* tools nothing else invoked."""
    meta, body = load_directive_by_id(directives_dir, "verify_project")
    assert "verify_output" in meta.tools
    for tool in ("verify_code_static", "verify_security", "verify_code_dynamic"):
        assert tool in meta.tools
    # The directive must preserve the verifier's fail-hard treatment of a
    # vacuous test phase.
    assert "No tests collected" in body or "no tests were collected" in body.lower()
    assert "fail" in body.lower()


@pytest.mark.parametrize(
    ("pytest_result", "expected_code"),
    [
        ({"returncode": 1, "stdout": "", "stderr": "No module named pytest"}, "PYTEST_MISSING"),
        ({"returncode": 5, "stdout": "no tests ran", "stderr": ""}, "NO_TESTS_COLLECTED"),
    ],
)
def test_dynamic_verifier_fails_when_test_phase_is_vacuous(
    monkeypatch, pytest_result, expected_code
):
    """A missing runner or empty collection must never make the gate green."""
    from types import SimpleNamespace

    from runtime_tools import verify_tools

    calls = 0

    def fake_run(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return SimpleNamespace(returncode=0, stdout="17\n", stderr="")
        if calls == 2:
            return SimpleNamespace(returncode=0, stdout="OK\n", stderr="")
        return SimpleNamespace(**pytest_result)

    monkeypatch.delenv(verify_tools._SANDBOX_MARKER, raising=False)
    monkeypatch.setattr(verify_tools.subprocess, "run", fake_run)

    result = verify_tools.verify_code_dynamic()

    assert result["passed"] is False
    assert any(finding["code"] == expected_code for finding in result["findings"])
    test_check = next(check for check in result["checks"] if check["name"] == "test_suite")
    assert test_check["passed"] is False


def test_dynamic_verifier_copies_test_catalogue():
    """The temporary project must contain the generated file its tests validate."""
    from runtime_tools import verify_tools

    assert "tests" in verify_tools._SOURCE_DIRS
    assert "docs" in verify_tools._SOURCE_DIRS


def test_test_coverage_audit_writes_only_to_a_writable_dir(directives_dir):
    from runtime_tools.file_tools import _WRITABLE_DIRS

    meta, body = load_directive_by_id(directives_dir, "test_coverage_audit")
    assert "write_file" in meta.tools
    assert "output/test-coverage-audit.md" in body
    assert "output" in _WRITABLE_DIRS, "the directive's report path must stay writable"


def test_verification_directives_are_registered_in_the_set(directives_dir):
    ids = {meta.id for meta, _ in (load_directive_by_id(directives_dir, p.stem)
                                   for p in sorted(directives_dir.glob("*.md")))}
    assert {"verify_project", "test_coverage_audit"} <= ids
