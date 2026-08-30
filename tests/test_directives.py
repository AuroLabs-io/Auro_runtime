"""
Shipped directive integrity.

Directives are content, not code, so nothing else in the suite catches a
directive that names a tool which no longer exists. That is the same failure
class as the stale policy tool name which once made the runtime unable to run
anything: it parses fine, ships fine, and fails at execution time.
"""

import re

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
def directives_dir():
    from auro_runtime.paths import get_directives_dir

    return get_directives_dir()


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


class TestValidateDirectiveResolvesTheAuthorityMount:
    """`validate_directive` reads through the same mounts as `read_file`.

    It used to resolve relative paths against the workspace alone. That agreed
    with the documented `directives/x.md` spelling only while a top-level
    mirror of the authority tree happened to sit inside the workspace; when the
    mirrors were retired, every shipped directive became File not found through
    the path the directives themselves instruct. These pin the resolution in
    both directions, because a reader that accepts the mount must still refuse
    an escape through it -- accepting more is the failure mode a permit-only
    test cannot see.

    Bound, measured rather than assumed: the refusal tests below do not pin the
    explicit containment check. Removing it alone leaves all seven passing,
    because `check_resource_plan` refuses an uncontained subject with the very
    same sentence, so the two layers are indistinguishable from outside. Only
    removing both makes five of these fail. They therefore prove that an escape
    is refused, not which layer refuses it -- and the duplication is deliberate
    depth, not an accident to be tidied away.
    """

    def test_the_directives_mount_resolves_to_the_packaged_authority(self, registry):
        from auro_runtime.paths import get_directives_dir
        from runtime_tools.validate_directive_tools import validate_directive

        for path in sorted(get_directives_dir().glob("*.md")):
            result = validate_directive(f"directives/{path.name}")
            assert result.get("valid") is True, f"{path.name}: {result.get('errors')}"

    def test_an_absolute_path_to_packaged_authority_is_accepted(self, registry):
        from auro_runtime.paths import get_directives_dir
        from runtime_tools.validate_directive_tools import validate_directive

        target = get_directives_dir() / "tool_catalog.md"
        assert validate_directive(str(target)).get("valid") is True

    @pytest.mark.parametrize(
        "path",
        [
            "directives/../../../../Windows/System32/drivers/etc/hosts",
            "../../Windows/System32/drivers/etc/hosts",
            "C:/Windows/System32/drivers/etc/hosts",
            "/etc/passwd",
        ],
    )
    def test_an_escape_through_or_around_the_mount_is_refused(self, path, registry):
        """Traversal is refused after resolution, not by inspecting the string."""
        from runtime_tools.validate_directive_tools import validate_directive

        result = validate_directive(path)
        assert result.get("valid") is False
        assert "outside the allowed project directory" in result["errors"][0]

    def test_a_sensitive_name_is_still_refused_under_the_mount(self, registry):
        """The mount must not become a way around the sensitive-file classifier."""
        from runtime_tools.validate_directive_tools import validate_directive

        for path in ("directives/.env.md", "output/.env.md"):
            result = validate_directive(path)
            assert result.get("valid") is False
            assert "sensitive file" in result["errors"][0]


# --- The verification directives specifically ---------------------------------


def test_verifiers_are_not_reachable_from_a_directive(directives_dir, registry):
    """
    The verifiers are operator functions and must stay unregistered.

    `verify_project` was cut on 2026-08-13. Driving it required the registries to
    load, the policies to validate, and a model to follow a seven-step protocol,
    so the only checkouts it could report on were the ones already working; a
    broken one refused the directive instead of explaining itself. Re-registering
    these would restore that path, and without the directive there would be
    nothing left to make it visible.
    """
    verifiers = ("verify_output", "verify_code_static", "verify_security", "verify_code_dynamic")

    for name in verifiers:
        assert name not in registry, f"{name} is registered as a tool again"

    for path in sorted(directives_dir.glob("*.md")):
        meta, _ = load_directive_by_id(directives_dir, path.stem)
        named = sorted(t for t in meta.tools if t in verifiers)
        assert not named, f"{path.name} grants verifier tools: {named}"


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
    assert {"test_coverage_audit"} <= ids


# --- Generated directive catalogue -------------------------------------------
#
# A directive count with nothing behind it reads as verified while nothing
# checks it. These three tests are what make docs/DIRECTIVES.md an artifact
# rather than a claim: it is current, drift is detectable, and an undescribed
# directive halts generation instead of shipping unlabelled.


def test_directive_catalogue_is_current(repo_root):
    """
    docs/DIRECTIVES.md is generated from directives/. A hand-maintained
    catalogue drifts, and a stale one is worse than none: it describes authority
    the runtime no longer grants.

    Regenerate with: python -m tests.directive_catalogue
    """
    from tests.directive_catalogue import collect, render

    catalogue = repo_root / "docs" / "DIRECTIVES.md"
    assert catalogue.is_file(), "docs/DIRECTIVES.md missing — run: python -m tests.directive_catalogue"
    assert catalogue.read_text(encoding="utf-8") == render(collect()), (
        "docs/DIRECTIVES.md is stale. Regenerate with: python -m tests.directive_catalogue"
    )


def test_directive_catalogue_would_detect_an_added_directive(repo_root):
    """
    Negative control for the test above. A drift check that cannot fail proves
    nothing, so this confirms the comparison is actually sensitive to the input:
    adding a directive must change the rendered output.
    """
    from tests.directive_catalogue import collect, render

    committed = (repo_root / "docs" / "DIRECTIVES.md").read_text(encoding="utf-8")
    with_extra = render(collect() + [("zz_probe", "task", "Synthetic probe.", ["echo"])])

    assert with_extra != committed, (
        "rendering an extra directive produced byte-identical output — "
        "the drift check cannot detect a new directive"
    )
    assert "zz_probe" in with_extra, "the added directive did not reach the output"


def test_directive_catalogue_refuses_an_undescribed_directive(tmp_path, monkeypatch):
    """
    A directive grants tool authority. Generation must halt on one it cannot
    describe rather than emitting a blank row, which would publish an authority
    grant with no account of what it is for.
    """
    from tests import directive_catalogue

    fake = tmp_path / "directives"
    fake.mkdir()
    (fake / "nameless.md").write_text(
        "---\nid: nameless\ntools: [echo]\ncategory: task\n---\n\nbody\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(directive_catalogue, "DIRECTIVES_DIR", fake)

    with pytest.raises(SystemExit) as exc_info:
        directive_catalogue.collect()
    assert "nameless.md" in str(exc_info.value)


# --- README directive count ---------------------------------------------------
#
# docs/DIRECTIVES.md is generated and cannot drift. The README is prose, and the
# count in it is the one directive figure a person types by hand, in a section
# whose argument is that nothing here is maintained by hand. This is the guard
# for that number.

_NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20,
}


def _readme_directive_counts(text: str) -> list[tuple[str, int]]:
    """
    [(token, value)] for every '<n> directives' claim in the README.

    Tokens that are not numbers ('no directives', 'short directives') are not
    count claims and are skipped. Matching on the noun rather than the full
    sentence keeps the guard alive through a rewrite of the prose around it.
    """
    found = []
    for token in re.findall(r"([A-Za-z]+|\d+)\s+directives\b", text):
        if token.isdigit():
            found.append((token, int(token)))
        elif token.lower() in _NUMBER_WORDS:
            found.append((token, _NUMBER_WORDS[token.lower()]))
    return found


def test_readme_directive_count_matches_the_shipped_set(repo_root):
    """
    The README states how many directives ship. Nothing generates that sentence,
    so it is the one directive figure that can go stale unnoticed while every
    generated artifact stays correct.

    Extend _NUMBER_WORDS if the count outgrows it.
    """
    from tests.directive_catalogue import collect

    actual = len(collect())
    readme = repo_root / "README.md"
    assert readme.is_file(), "README.md missing"

    claims = _readme_directive_counts(readme.read_text(encoding="utf-8"))
    assert claims, (
        f"README.md states no directive count, but {actual} directives ship. "
        "Expected a phrase like '14 directives' or 'Fourteen directives'. "
        "If the wording changed, restore a count or delete this test deliberately."
    )

    stale = [token for token, value in claims if value != actual]
    assert not stale, (
        f"README.md claims {stale} directives; {actual} ship. Update the README."
    )


def test_readme_directive_count_guard_would_catch_a_stale_number(repo_root):
    """
    Negative control. A guard that passes on any input proves nothing, so this
    confirms the parser reads the number rather than merely finding the word.
    """
    real = (repo_root / "README.md").read_text(encoding="utf-8")
    assert _readme_directive_counts(real), "no count claim found in the real README"

    assert _readme_directive_counts("Ninety directives ship.") == []
    assert _readme_directive_counts("No directives are exposed.") == []
    assert _readme_directive_counts("Fifteen directives ship.") == [("Fifteen", 15)]
    assert _readme_directive_counts("14 directives ship.") == [("14", 14)]
