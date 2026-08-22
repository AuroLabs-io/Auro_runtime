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


# ---------------------------------------------------------------------------
# The withheld-pack gate.
#
# The pack is withheld because its contents are transferable technique, and its
# filenames and parametrized ids are that technique. These tests hold the line
# that a verdict may travel and the corpus may not.
# ---------------------------------------------------------------------------

_SECRET_PAYLOAD = "%6c%6f%63%61%6c%68%6f%73%74"


def _pack(tmp_path: Path, body: str, name: str = "test_named_after_its_contents.py") -> Path:
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
    # The filename describes the contents, so it must appear nowhere in a record
    # that travels beside a published artifact.
    assert "test_named_after_its_contents" not in json.dumps(identity)


def test_private_pack_digest_binds_to_content(tmp_path):
    pack = _pack(tmp_path, "def test_ok():\n    assert True\n")
    before = _private_pack_identity(pack)["digest"]

    (pack / "test_named_after_its_contents.py").write_text(
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
    """The disclosure control, not just the refusal.

    A failing case prints its own parametrized id, and for the real pack those
    ids are the payloads. This plants one, fails on it, and proves it reaches
    neither the exception nor anything derived from it.
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
    assert "test_named_after_its_contents" not in message


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
