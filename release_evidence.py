"""Build and verify a release candidate from one explicit Git identity.

This module is operator-facing release infrastructure.  It is deliberately not
registered as a runtime tool: a model must not be able to manufacture release
evidence or select the source identity that evidence names.

The command refuses a dirty checkout, proves that HEAD and the index are the
expected commit tree, exports that commit with ``git archive``, builds wheel and
sdist from the export, and runs the mandatory distribution matrix against those
exact files.  Only after every gate passes are the artifacts and their evidence
record copied to the requested output directory.

A withheld regression suite may be supplied with ``--private-pack``.  It runs
inside the export, so it is bound to the same commit as the artifacts by
construction rather than by assertion, and it is identified in the record by
digest alone.  It cannot be supplied by CI, which is why its absence is recorded
as ``release_complete: false`` instead of being left to look like a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


_FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
_ARTIFACT_SUFFIXES = (".whl", ".tar.gz")
_PYTEST_PASSED = re.compile(r"(?:^|\s)(?P<count>\d+) passed(?:,|\s|$)")


class ReleaseEvidenceError(RuntimeError):
    """The requested evidence could not be bound to one safe source identity."""


@dataclass(frozen=True)
class SourceIdentity:
    commit: str
    commit_tree: str
    index_tree: str
    status: str = "clean"
    # What the evidence is evidence *for*. The three ids above bind a tree; none
    # of them says whether this repository would ever publish it. CI runs this
    # gate on every push and on pull requests, so most runs are for a feature
    # branch or for a refs/pull/N/merge commit that exists only inside GitHub --
    # and without these two fields every one of those produced a record
    # indistinguishable from a real release candidate.
    ref: str | None = None
    publication_candidate: bool = False


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 900,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseEvidenceError(
            f"command could not complete: {command[0]}"
        ) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        if len(detail) > 2000:
            detail = detail[-2000:]
        raise ReleaseEvidenceError(
            f"command failed ({result.returncode}): {' '.join(command)}"
            + (f"\n{detail}" if detail else "")
        )
    return result


def _git(repo_root: Path, *args: str) -> str:
    return _run(
        ["git", "-c", f"safe.directory={repo_root.as_posix()}", *args],
        cwd=repo_root,
        timeout=60,
    ).stdout.strip()


def inspect_source_identity(
    repo_root: Path,
    expected_commit: str,
    source_ref: str | None = None,
    publication_candidate: bool = False,
) -> SourceIdentity:
    """
    Refuse unless HEAD, index, and the clean checkout are one named commit.

    ``source_ref`` is recorded verbatim and ``publication_candidate`` is the
    caller's assertion that the ref is one this repository publishes from. This
    command cannot know that on its own: the publishable branch is repository
    policy, and a branch list hardcoded here would be an inventory maintained by
    hand wearing the costume of a control. Recording the ref beside the
    assertion is what makes the assertion auditable.

    The valence of omission is refusal. An unlabelled run is **not** a
    publication candidate, because the failure that matters is a record for a
    tree nobody will publish being mistaken for a release candidate, and that
    failure needs the flag to default the other way.
    """
    repo_root = repo_root.resolve()
    if _FULL_COMMIT.fullmatch(expected_commit) is None:
        raise ReleaseEvidenceError(
            "expected commit must be the full 40-character Git object id"
        )

    ref = source_ref or None
    if publication_candidate and ref is not None and ref.startswith("refs/pull/"):
        # The one wrong combination recognisable without knowing branch policy.
        # A pull-request ref names a commit that lives only inside GitHub and
        # will never appear in published history, so asserting it is publishable
        # is always a mistake. Refuse rather than record it: a record carrying a
        # contradiction is worse than one that declines to be written.
        raise ReleaseEvidenceError(
            f"pull-request ref {ref} cannot be a publication candidate"
        )

    commit = _git(repo_root, "rev-parse", "--verify", "HEAD^{commit}").lower()
    if commit != expected_commit.lower():
        raise ReleaseEvidenceError(
            f"expected commit {expected_commit.lower()}, but HEAD is {commit}"
        )

    status = _git(repo_root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        count = len(status.splitlines())
        raise ReleaseEvidenceError(
            f"source checkout is dirty ({count} path(s)); inspect git status locally"
        )

    commit_tree = _git(repo_root, "rev-parse", "--verify", "HEAD^{tree}").lower()
    index_tree = _git(repo_root, "write-tree").lower()
    if index_tree != commit_tree:
        raise ReleaseEvidenceError(
            f"index tree {index_tree} does not match commit tree {commit_tree}"
        )

    return SourceIdentity(
        commit=commit,
        commit_tree=commit_tree,
        index_tree=index_tree,
        ref=ref,
        publication_candidate=bool(publication_candidate),
    )


def _safe_extract_git_archive(archive_path: Path, destination: Path) -> None:
    destination = destination.resolve()
    with tarfile.open(archive_path, "r:") as archive:
        members = archive.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            try:
                target.relative_to(destination)
            except ValueError as exc:
                raise ReleaseEvidenceError(
                    "git archive contained a path outside the source root"
                ) from exc
            if member.issym() or member.islnk():
                raise ReleaseEvidenceError(
                    f"git archive contains unsupported link: {member.name}"
                )
        archive.extractall(destination, members=members)


def export_commit(repo_root: Path, commit: str, destination: Path) -> None:
    """Export exactly ``commit``; ambient tracked, untracked, and ignored files stay out."""
    destination.mkdir(parents=True, exist_ok=False)
    archive_path = destination.parent / "source.tar"
    _run(
        [
            "git",
            "-c",
            f"safe.directory={repo_root.resolve().as_posix()}",
            "archive",
            "--format=tar",
            f"--output={archive_path}",
            commit,
        ],
        cwd=repo_root.resolve(),
        timeout=120,
    )
    _safe_extract_git_archive(archive_path, destination)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_records(dist_dir: Path) -> list[dict[str, object]]:
    artifacts = sorted(
        path
        for path in dist_dir.iterdir()
        if path.is_file() and path.name.endswith(_ARTIFACT_SUFFIXES)
    )
    wheels = [path for path in artifacts if path.suffix == ".whl"]
    sdists = [path for path in artifacts if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1 or len(artifacts) != 2:
        raise ReleaseEvidenceError(
            "candidate build must produce exactly one wheel and one source distribution"
        )
    return [
        {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in artifacts
    ]


def _version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "unavailable"


def _last_nonempty_line(value: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return lines[-1] if lines else "completed with exit code 0"


def _pytest_evidence(stdout: str) -> dict[str, object]:
    """Require evidence that the matrix ran and passed a non-empty test set."""
    summary = _last_nonempty_line(stdout)
    match = _PYTEST_PASSED.search(summary)
    if match is None:
        raise ReleaseEvidenceError(
            f"distribution matrix returned success without a passed-test count: {summary}"
        )
    passed = int(match.group("count"))
    if passed == 0:
        raise ReleaseEvidenceError("distribution matrix ran zero passing tests")
    return {"passed": True, "test_count": passed, "summary": summary}


def _private_pack_identity(pack_dir: Path) -> dict[str, object]:
    """Identify the pack by digest alone.

    Deliberately records no filenames.  The pack is withheld because its
    contents are transferable technique, and its filenames describe those
    contents, so naming them in a record that travels with a published artifact
    would republish the part that matters.  A digest is checkable by anyone
    holding the pack and says nothing to anyone who does not.
    """
    files = sorted(path for path in pack_dir.glob("test_*.py") if path.is_file())
    if not files:
        raise ReleaseEvidenceError(
            f"no test modules found in the supplied private pack: {pack_dir}"
        )
    hashes = sorted(_sha256(path) for path in files)
    combined = hashlib.sha256("".join(hashes).encode("ascii")).hexdigest()
    return {"file_count": len(files), "file_sha256": hashes, "digest": combined}


def _run_private_pack(source_root: Path, pack_dir: Path) -> dict[str, object]:
    """Run the withheld pack against the exported commit and return a verdict.

    The binding item 4 asks for is structural rather than asserted: the pack runs
    inside the ``git archive`` export, so it cannot execute against different
    source than the artifacts were built from.

    Output handling is not the usual ``_run`` path.  A failing case in this pack
    prints its own parametrized id, and those ids are the payloads, so neither a
    traceback nor a node id may reach the evidence record or the operator's
    terminal.  Tracebacks are suppressed at the runner and only the final
    summary line -- counts, never names -- is retained.  An operator diagnosing
    a failure re-runs the pack locally, where the full output is safe.
    """
    identity = _private_pack_identity(pack_dir)
    target = source_root / "tests" / "local"
    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(pack_dir.glob("test_*.py")):
        shutil.copy2(path, target / path.name)

    try:
        result = subprocess.run(
            [
                sys.executable, "-B", "-m", "pytest",
                "tests/local",
                "-o", "addopts=",
                "-q", "--tb=no", "-p", "no:cacheprovider",
            ],
            cwd=source_root,
            text=True,
            capture_output=True,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseEvidenceError("private pack could not complete") from exc

    summary = _last_nonempty_line(result.stdout)
    if result.returncode != 0:
        raise ReleaseEvidenceError(f"private pack did not pass: {summary}")

    match = _PYTEST_PASSED.search(summary)
    if match is None:
        raise ReleaseEvidenceError(
            f"private pack returned success without a passed-test count: {summary}"
        )
    passed = int(match.group("count"))
    if passed == 0:
        raise ReleaseEvidenceError("private pack ran zero passing tests")

    return {"status": "passed", "test_count": passed, "summary": summary, **identity}


def build_release_evidence(
    repo_root: Path,
    expected_commit: str,
    output_dir: Path,
    private_pack: Path | None = None,
    source_ref: str | None = None,
    publication_candidate: bool = False,
) -> Path:
    """Build, test, and report one commit-bound publication candidate."""
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    identity = inspect_source_identity(
        repo_root, expected_commit, source_ref, publication_candidate
    )

    if output_dir.exists() and any(output_dir.iterdir()):
        raise ReleaseEvidenceError(
            f"output directory is not empty: {output_dir}"
        )

    with tempfile.TemporaryDirectory(prefix="auro_release_") as raw_temp:
        temp_root = Path(raw_temp)
        source_root = temp_root / "source"
        candidate_dir = temp_root / "candidate"
        candidate_dir.mkdir()
        export_commit(repo_root, identity.commit, source_root)

        build_result = _run(
            [
                sys.executable,
                "-B",
                "-m",
                "build",
                "--outdir",
                str(candidate_dir),
                str(source_root),
            ],
            cwd=temp_root,
        )
        artifact_records = _artifact_records(candidate_dir)

        _run(
            [
                sys.executable,
                "-B",
                "-m",
                "twine",
                "check",
                *(str(candidate_dir / item["filename"]) for item in artifact_records),
            ],
            cwd=temp_root,
        )

        test_env = os.environ.copy()
        test_env["AURO_RUN_DISTRIBUTION_TESTS"] = "1"
        test_env["AURO_DISTRIBUTION_DIR"] = str(candidate_dir)
        test_result = _run(
            [
                sys.executable,
                "-B",
                "-m",
                "pytest",
                "tests/test_distribution_install.py",
                "-m",
                "distribution",
                "-p",
                "no:cacheprovider",
            ],
            cwd=source_root,
            env=test_env,
        )
        distribution_evidence = _pytest_evidence(test_result.stdout)

        if private_pack is not None:
            private_pack_evidence = _run_private_pack(source_root, private_pack)
        else:
            private_pack_evidence = {
                "status": "not_run",
                "reason": "no private pack supplied to this run",
            }

        if _artifact_records(candidate_dir) != artifact_records:
            raise ReleaseEvidenceError(
                "candidate artifacts changed while the distribution matrix ran"
            )

        final_identity = inspect_source_identity(
            repo_root, expected_commit, source_ref, publication_candidate
        )
        if final_identity != identity:
            raise ReleaseEvidenceError(
                "source identity changed while release evidence was being produced"
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        for item in artifact_records:
            shutil.copy2(candidate_dir / str(item["filename"]), output_dir)

        evidence = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": asdict(identity),
            "build_source": "git archive of source.commit",
            "artifacts": artifact_records,
            "toolchain": {
                "python": sys.version.split()[0],
                "build": _version("build"),
                "twine": _version("twine"),
                "pytest": _version("pytest"),
            },
            "gates": {
                "clean_before_and_after": True,
                "twine_check": "passed",
                "distribution_matrix": distribution_evidence,
                "private_pack": private_pack_evidence,
            },
            # Every gate ran and passed, or this candidate is not publishable.
            # A gate that did not run has not decided the candidate is sound, it
            # has failed to look, and the two must not be indistinguishable in
            # the record.  CI cannot supply the private pack, so its retained
            # candidates are correctly marked incomplete rather than silently
            # counted as verified.
            "release_complete": private_pack_evidence["status"] == "passed",
            "build_summary": _last_nonempty_line(build_result.stdout),
        }
        evidence_path = output_dir / "release-evidence.json"
        evidence_path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(json.dumps(evidence, indent=2, sort_keys=True))
    return evidence_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and verify artifacts from one clean, explicit Git commit."
    )
    parser.add_argument(
        "--expected-commit",
        required=True,
        help="full 40-character commit id that HEAD, index, build, and report must share",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="source checkout (default: current directory)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist"),
        help="empty directory that receives the verified artifacts and evidence",
    )
    parser.add_argument(
        "--source-ref",
        default=None,
        help=(
            "the ref this build was triggered for, recorded verbatim so the "
            "--publication-candidate assertion beside it can be audited"
        ),
    )
    parser.add_argument(
        "--publication-candidate",
        action="store_true",
        help=(
            "assert that --source-ref is one this repository publishes from. "
            "Omitted means no: an unlabelled run is recorded as evidence for a "
            "tree, not as a release candidate"
        ),
    )
    parser.add_argument(
        "--private-pack",
        type=Path,
        default=None,
        help=(
            "directory holding the withheld regression suite; without it the "
            "record is marked release_complete: false rather than reporting a "
            "gate that did not run as one that passed"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        build_release_evidence(
            args.repo_root,
            args.expected_commit,
            args.output_dir,
            args.private_pack,
            args.source_ref,
            args.publication_candidate,
        )
    except ReleaseEvidenceError as exc:
        print(f"release evidence refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
