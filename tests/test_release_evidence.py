"""Commit-bound release evidence and dirty-tree refusal contracts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from release_evidence import (
    ReleaseEvidenceError,
    _private_pack_identity,
    _pytest_evidence,
    _release_is_complete,
    _run_private_pack,
    export_commit,
    inspect_source_identity,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={repo.as_posix()}", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


@pytest.fixture
def committed_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "Release Evidence Test")
    _git(repo, "config", "user.email", "release-evidence@example.invalid")
    (repo / "tracked.txt").write_text("committed\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-m", "fixture")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_release_identity_binds_head_index_and_commit_tree(committed_repo):
    repo, commit = committed_repo

    identity = inspect_source_identity(repo, commit)

    assert identity.commit == commit
    assert identity.commit_tree == _git(repo, "rev-parse", "HEAD^{tree}")
    assert identity.index_tree == identity.commit_tree
    assert identity.status == "clean"


def test_release_identity_refuses_a_different_expected_commit(committed_repo):
    repo, _commit = committed_repo

    with pytest.raises(ReleaseEvidenceError, match="but HEAD is"):
        inspect_source_identity(repo, "0" * 40)


def test_release_identity_refuses_untracked_or_modified_source(committed_repo):
    repo, commit = committed_repo
    (repo / "tracked.txt").write_text("ambient modification\n", encoding="utf-8")
    (repo / "untracked.txt").write_text("ambient addition\n", encoding="utf-8")

    with pytest.raises(ReleaseEvidenceError, match="source checkout is dirty"):
        inspect_source_identity(repo, commit)


def test_commit_export_excludes_ambient_working_tree_content(
    committed_repo,
    tmp_path,
):
    repo, commit = committed_repo
    (repo / "tracked.txt").write_text("ambient modification\n", encoding="utf-8")
    (repo / "untracked.txt").write_text("ambient addition\n", encoding="utf-8")
    exported = tmp_path / "exported"

    export_commit(repo, commit, exported)

    assert (exported / "tracked.txt").read_text(encoding="utf-8") == "committed\n"
    assert not (exported / "untracked.txt").exists()


def test_distribution_evidence_requires_a_nonzero_passed_count():
    assert _pytest_evidence("....... [100%]\n7 passed in 1.25s\n") == {
        "passed": True,
        "test_count": 7,
        "summary": "7 passed in 1.25s",
    }

    with pytest.raises(ReleaseEvidenceError, match="without a passed-test count"):
        _pytest_evidence("7 skipped in 0.05s\n")


# --- The published verdict is derived from the gates it summarises ------------


def test_release_is_complete_only_when_every_mandatory_gate_passed():
    passing = {"passed": True, "test_count": 7, "summary": "7 passed"}
    other = {"passed": True, "test_count": 675, "summary": "675 passed"}

    assert _release_is_complete(passing, other) is True


def test_a_failed_gate_denies_release_completion():
    passing = {"passed": True, "test_count": 7, "summary": "7 passed"}
    failed = {"passed": False, "test_count": 0, "summary": "1 failed"}

    assert _release_is_complete(passing, failed) is False
    assert _release_is_complete(failed, passing) is False


def test_a_gate_reporting_no_verdict_is_not_a_pass():
    """A gate carrying no `passed` key has not decided the candidate is sound.

    This is the fail-closed half: a gate added to the record but never given a
    verdict must not be counted as one that cleared.
    """
    passing = {"passed": True, "test_count": 7, "summary": "7 passed"}
    silent = {"status": "not_run", "reason": "nothing supplied"}

    assert _release_is_complete(passing, silent) is False


def test_release_completion_is_derived_rather_than_asserted():
    """Negative control.

    If the verdict were hardcoded, every case above would pass identically. This
    fails unless the value actually tracks the gates it is given.
    """
    failed = {"passed": False, "summary": "1 failed"}

    assert _release_is_complete(failed) is not _release_is_complete({"passed": True})


# ---------------------------------------------------------------------------
# The additional-directory gate.
#
# The evidence record travels with a published artifact, so it carries a verdict
# and counts. These tests hold the line that no filename, node id or traceback
# from the supplied directory reaches the record or the operator's terminal.
# ---------------------------------------------------------------------------

_SECRET_PAYLOAD = "unique-marker-that-must-not-reach-the-record"


def _pack(tmp_path: Path, body: str, name: str = "test_marker_in_the_filename.py") -> Path:
    pack = tmp_path / "pack"
    pack.mkdir(exist_ok=True)
    (pack / name).write_text(body, encoding="utf-8")
    return pack


def _source_root(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    (root / "tests").mkdir(parents=True)
    return root


def test_private_pack_is_identified_by_digest_and_never_by_name(tmp_path):
    pack = _pack(tmp_path, "def test_ok():\n    assert True\n")

    identity = _private_pack_identity(pack)

    assert identity["file_count"] == 1
    assert len(identity["file_sha256"]) == 1
    assert len(identity["digest"]) == 64
    # A filename can describe what it holds, so none may appear in a record that
    # travels beside a published artifact.
    assert "test_marker_in_the_filename" not in json.dumps(identity)


def test_private_pack_digest_binds_to_content(tmp_path):
    pack = _pack(tmp_path, "def test_ok():\n    assert True\n")
    before = _private_pack_identity(pack)["digest"]

    (pack / "test_marker_in_the_filename.py").write_text(
        "def test_ok():\n    assert 1 == 1\n", encoding="utf-8"
    )

    assert _private_pack_identity(pack)["digest"] != before


def test_private_pack_refuses_a_directory_with_no_test_modules(tmp_path):
    empty = tmp_path / "pack"
    empty.mkdir()

    with pytest.raises(ReleaseEvidenceError, match="no test modules found"):
        _private_pack_identity(empty)


def test_private_pack_verdict_records_a_nonzero_count(tmp_path):
    root = _source_root(tmp_path)
    pack = _pack(tmp_path, "def test_a():\n    assert True\n\n\ndef test_b():\n    assert True\n")

    evidence = _run_private_pack(root, pack)

    assert evidence["status"] == "passed"
    assert evidence["test_count"] == 2
    assert evidence["file_count"] == 1


def test_a_failing_private_pack_refuses_without_disclosing_the_case(tmp_path):
    """The output control, not just the refusal.

    A failing case prints its own parametrized id. This plants a unique marker in
    one, fails on it, and proves the marker reaches neither the exception nor
    anything derived from it.
    """
    root = _source_root(tmp_path)
    pack = _pack(
        tmp_path,
        "import pytest\n"
        "\n"
        f"@pytest.mark.parametrize('host', ['{_SECRET_PAYLOAD}'])\n"
        "def test_refuses(host):\n"
        "    assert host == 'this fails'\n",
    )

    with pytest.raises(ReleaseEvidenceError) as caught:
        _run_private_pack(root, pack)

    message = str(caught.value)
    assert "private pack did not pass" in message
    assert _SECRET_PAYLOAD not in message
    assert "test_refuses" not in message
    assert "test_marker_in_the_filename" not in message


def test_private_pack_that_runs_nothing_is_not_a_pass(tmp_path):
    """A pack that proved nothing must not be recorded as one that passed.

    Two branches can refuse this — a non-zero exit, or a zero exit whose summary
    carries no passed count — and which one fires depends on the pytest version's
    treatment of a module-level skip. The property under test is that no verdict
    survives either way, so it asserts the refusal rather than the branch.
    """
    root = _source_root(tmp_path)
    pack = _pack(tmp_path, "import pytest\n\npytest.skip('nothing here', allow_module_level=True)\n")

    with pytest.raises(ReleaseEvidenceError) as caught:
        _run_private_pack(root, pack)

    assert "passed" not in str(caught.value).replace("did not pass", "")


# --- What the evidence is evidence *for* -----------------------------------
#
# The identity check binds a commit, its tree and the index. None of that says
# whether the commit is one this repository would ever publish. CI runs the gate
# on every push and on pull requests, so most runs are for a feature branch or
# for a `refs/pull/N/merge` commit that exists only as a GitHub ref -- and every
# one of them produced a record indistinguishable from a real release candidate.
# That is the failure this whole gate exists to prevent, reached from the other
# side: evidence bound to a tree nobody will publish.

PUBLISHABLE_REFS = [
    pytest.param("refs/heads/main", id="default-branch"),
    pytest.param("refs/tags/v0.1.0", id="release-tag"),
]

UNPUBLISHABLE_REFS = [
    pytest.param("refs/pull/7/merge", id="pull-request-merge"),
    pytest.param("refs/pull/7/head", id="pull-request-head"),
    pytest.param(None, id="ref-not-supplied"),
    pytest.param("", id="ref-empty"),
    pytest.param("HEAD", id="detached-head"),
    pytest.param("refs/heads/harden/some-branch", id="feature-branch"),
]


def test_the_source_ref_reaches_the_record_verbatim(committed_repo):
    """The ref is what makes the publication claim auditable, so it is recorded as given."""
    repo, commit = committed_repo

    identity = inspect_source_identity(
        repo, commit, source_ref="refs/heads/main", publication_candidate=True
    )

    assert identity.ref == "refs/heads/main"


@pytest.mark.parametrize("ref", PUBLISHABLE_REFS)
def test_an_asserted_publishable_ref_is_recorded_as_a_candidate(committed_repo, ref):
    """
    The non-vacuity anchor for every case below.

    A field hardcoded `False` satisfies all of them, and nothing would show.
    """
    repo, commit = committed_repo

    identity = inspect_source_identity(
        repo, commit, source_ref=ref, publication_candidate=True
    )

    assert identity.publication_candidate is True


@pytest.mark.parametrize("ref", UNPUBLISHABLE_REFS)
def test_a_ref_nobody_asserted_is_not_a_publication_candidate(committed_repo, ref):
    """
    Fail closed, and state the valence: an unlabelled run is not a candidate.

    `release_evidence.py` cannot know which branch a repository publishes from
    without guessing it, and a guessed branch list would be an inventory
    maintained by hand wearing the costume of a control. The caller asserts;
    omission, an empty value and an unrecognised value all resolve to false.
    """
    repo, commit = committed_repo

    identity = inspect_source_identity(repo, commit, source_ref=ref)

    assert identity.publication_candidate is False


def test_a_pull_request_ref_cannot_be_asserted_as_a_publication_candidate(committed_repo):
    """
    The one wrong combination that needs no branch policy to recognise.

    A pull-request ref names a commit that exists only inside GitHub and will
    never appear in published history, so asserting it is publishable is always a
    mistake. Refused rather than recorded, because a record that carries a
    contradiction is worse than one that refuses to be written.
    """
    repo, commit = committed_repo

    with pytest.raises(ReleaseEvidenceError, match="pull-request ref"):
        inspect_source_identity(
            repo, commit, source_ref="refs/pull/7/merge", publication_candidate=True
        )
