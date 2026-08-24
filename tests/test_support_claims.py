"""The package's declared support surface must not exceed what CI exercises.

`classifiers`, `Provides-Extra` and `Requires-Python` are published claims: an
adopter reads "Programming Language :: Python :: 3.13" on the index page and
concludes the project runs there. Nothing previously connected those claims to
the matrix that would prove them, so a classifier could be added -- or a matrix
leg dropped -- and the suite would stay green while the package advertised
support nobody tests.

Both sides are derived at check time. The claim comes from the installed
distribution metadata rather than from `pyproject.toml`, because metadata is
what a reader actually sees; the proof comes from `.github/workflows/ci.yml`.
Neither is copied here. A list in this file would be a second copy of what those
two producers already say, and two pins that can disagree are worse than one.

The comparison runs in **both directions**, because the dangerous drift is not
only the obvious one. A claim wider than the matrix reads as covered and is not
(camouflage); a matrix leg no classifier claims is work nobody reviewed and an
adopter is never told about (understatement).

**What this does not reach.** It proves the workflow *declares* a leg, not that
the leg passed -- a red run on 3.10 is CI's finding, not this file's. It reads
the workflow as written rather than as GitHub expanded it, so a leg reached only
through an `include:` fragment or a reusable workflow is invisible here. And it
says nothing about whether an extra's dependency actually resolves at install
time; it checks that some CI step asks for it.
"""

from __future__ import annotations

import importlib.metadata
import pathlib
import re

import pytest
import yaml

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_DISTRIBUTION = "auro-runtime"

# GitHub runner label -> the trove classifier that claims that platform.
#
# This mapping is hand-maintained and is the one inventory this file cannot
# derive, because it joins two vocabularies that share no producer. It fails
# closed: an unmapped runner label raises rather than being skipped, so adding a
# macos leg forces the classifier decision instead of passing quietly. That is
# the valence chosen deliberately -- an unrecognised runner means "I cannot tell
# what this proves", and the safe reading of that is failure, not coverage.
_RUNNER_CLASSIFIER = {
    "ubuntu": "Operating System :: POSIX :: Linux",
    "windows": "Operating System :: Microsoft :: Windows",
    "macos": "Operating System :: MacOS",
}

# Claims that range over an open set. No matrix can prove one, because the set
# of operating systems is not enumerable in advance -- the same reason a close
# condition over an open domain is not closable by checking. Narrow it to the
# platforms actually run, or it is an unfalsifiable claim on a public index page.
_UNPROVABLE_CLASSIFIERS = {
    "Operating System :: OS Independent": (
        "claims every platform that exists or will exist; no CI matrix can "
        "prove it, so it cannot be distinguished from an untested guess"
    ),
}

_PY_CLASSIFIER = re.compile(r"^Programming Language :: Python :: (?P<version>\d+\.\d+)$")
_EXTRA_INSTALL = re.compile(r"\[(?P<extras>[A-Za-z0-9_,\-\s]+)\]")


def _workflow() -> dict:
    """The CI workflow as a mapping, or a failure naming why it could not be read."""
    if not _WORKFLOW.is_file():
        pytest.fail(f"no CI workflow at {_WORKFLOW}: nothing proves any support claim")
    loaded = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not loaded.get("jobs"):
        pytest.fail(f"{_WORKFLOW} parsed to no jobs; the proof side is empty")
    return loaded


def _jobs() -> dict:
    return _workflow()["jobs"]


def _proved_python_versions() -> set[str]:
    """Python versions some CI job runs on, from matrix legs and pinned setups."""
    found: set[str] = set()
    for job in _jobs().values():
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        for value in matrix.get("python-version", []):
            found.add(str(value))
        for step in job.get("steps") or []:
            pinned = (step.get("with") or {}).get("python-version")
            if pinned is not None and "matrix" not in str(pinned):
                found.add(str(pinned))
    return found


def _proved_runners() -> set[str]:
    """Runner families some CI job runs on, from matrix legs and literal runs-on."""
    found: set[str] = set()
    for job in _jobs().values():
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        labels = [str(value) for value in matrix.get("os", [])]
        runs_on = job.get("runs-on")
        if isinstance(runs_on, str) and "matrix" not in runs_on:
            labels.append(runs_on)
        for label in labels:
            family = label.split("-")[0]
            if family not in _RUNNER_CLASSIFIER:
                pytest.fail(
                    f"CI runs on {label!r}, which no entry in _RUNNER_CLASSIFIER "
                    "maps to a platform classifier. Add the mapping and decide "
                    "whether the package now claims that platform."
                )
            found.add(family)
    return found


def _installed_extras() -> set[str]:
    """Extras some CI step asks pip to install, read from the run commands."""
    found: set[str] = set()
    for job in _jobs().values():
        for step in job.get("steps") or []:
            command = step.get("run")
            if not command or "pip install" not in command:
                continue
            for match in _EXTRA_INSTALL.finditer(command):
                for extra in match.group("extras").split(","):
                    cleaned = extra.strip()
                    if cleaned:
                        found.add(cleaned)
    return found


def _metadata():
    try:
        return importlib.metadata.metadata(_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover
        pytest.fail(
            f"{_DISTRIBUTION} is not installed, so its published claims cannot "
            "be read. Install it (editable is fine) before running this file."
        )


def _classifiers() -> list[str]:
    found = _metadata().get_all("Classifier") or []
    if not found:
        pytest.fail(
            "the distribution declares no classifiers; an empty claim set would "
            "pass every comparison below without proving anything"
        )
    return list(found)


def _claimed_python_versions() -> set[str]:
    return {
        match.group("version")
        for match in (_PY_CLASSIFIER.match(entry) for entry in _classifiers())
        if match is not None
    }


def _claimed_platform_classifiers() -> set[str]:
    return {
        entry for entry in _classifiers() if entry.startswith("Operating System ::")
    }


def _declared_extras() -> set[str]:
    return set(_metadata().get_all("Provides-Extra") or [])


class TestTheProofSideIsRealBeforeAnythingIsComparedAgainstIt:
    """A comparison against an empty proof set is a pass that checked nothing."""

    def test_ci_declares_python_versions_to_prove_against(self):
        assert _proved_python_versions(), (
            "no CI job names a python-version; every version claim below would "
            "then be compared against an empty set"
        )

    def test_ci_declares_runners_to_prove_against(self):
        assert _proved_runners(), "no CI job names a runner to prove a platform claim"


class TestClaimedSupportIsExercised:
    """Camouflage: a claim wider than the matrix reads as covered and is not."""

    def test_every_claimed_python_version_runs_in_ci(self):
        unproved = _claimed_python_versions() - _proved_python_versions()
        assert not unproved, (
            f"classifiers claim Python {sorted(unproved)}, which no CI job runs. "
            "Add the matrix leg or drop the classifier."
        )

    def test_every_claimed_platform_runs_in_ci(self):
        proved = {_RUNNER_CLASSIFIER[family] for family in _proved_runners()}
        unproved = _claimed_platform_classifiers() - proved
        assert not unproved, (
            f"classifiers claim {sorted(unproved)}, which no CI runner proves. "
            "Add the runner or narrow the classifier."
        )

    def test_no_claim_ranges_over_a_set_no_matrix_can_close(self):
        offenders = _claimed_platform_classifiers() & set(_UNPROVABLE_CLASSIFIERS)
        assert not offenders, "; ".join(
            f"{entry!r}: {_UNPROVABLE_CLASSIFIERS[entry]}" for entry in sorted(offenders)
        )

    def test_every_declared_extra_is_installed_somewhere_in_ci(self):
        unproved = _declared_extras() - _installed_extras()
        assert not unproved, (
            f"the package offers extras {sorted(unproved)} that no CI step "
            "installs, so nothing would notice if one stopped resolving."
        )


class TestExercisedSupportIsClaimed:
    """Understatement: a tested leg nobody claims is work an adopter never hears about."""

    def test_every_python_version_ci_runs_is_claimed(self):
        unclaimed = _proved_python_versions() - _claimed_python_versions()
        assert not unclaimed, (
            f"CI runs Python {sorted(unclaimed)} with no classifier claiming it; "
            "an adopter reading the index page is not told it is supported."
        )

    def test_every_platform_ci_runs_is_claimed(self):
        proved = {_RUNNER_CLASSIFIER[family] for family in _proved_runners()}
        unclaimed = proved - _claimed_platform_classifiers()
        assert not unclaimed, (
            f"CI proves {sorted(unclaimed)} with no classifier claiming it."
        )

    def test_the_requires_python_floor_is_the_lowest_version_ci_runs(self):
        floor = (_metadata().get("Requires-Python") or "").strip()
        lowest = min(
            _proved_python_versions(), key=lambda v: tuple(map(int, v.split(".")))
        )
        assert floor == f">={lowest}", (
            f"Requires-Python is {floor!r} but the lowest version CI runs is "
            f"{lowest}. The floor is a claim about what installs, and an "
            "untested floor is the one adopters hit first."
        )


class TestTheMetadataReadHereIsNotStale:
    """Installed metadata is a build artifact, not a live view of the source.

    An editable install does not regenerate it when `pyproject.toml` changes, so
    every check above can audit a claim the project no longer makes and pass
    against a substrate that stopped matching. This compares the two and reports
    the drift rather than trusting the install.
    """

    def test_installed_classifiers_match_the_source_of_record(self):
        source = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        block = re.search(r"^classifiers\s*=\s*\[(.*?)^\]", source, re.S | re.M)
        assert block is not None, "no classifiers array found in pyproject.toml"
        # Comments inside the array carry quoted prose; only the entries count.
        entries = [
            line
            for line in block.group(1).splitlines()
            if not line.strip().startswith("#")
        ]
        declared = set(re.findall(r'"([^"]+)"', " ".join(entries)))
        installed = set(_classifiers())
        assert declared == installed, (
            "pyproject.toml and the installed metadata disagree about the "
            f"classifiers. Only in source: {sorted(declared - installed)}; only "
            f"in the install: {sorted(installed - declared)}. Reinstall with "
            "`pip install -e .` so the checks above audit the current claim."
        )
