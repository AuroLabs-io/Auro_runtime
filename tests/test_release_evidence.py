"""Commit-bound release evidence and dirty-tree refusal contracts."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from release_evidence import (
    ReleaseEvidenceError,
    _pytest_evidence,
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
