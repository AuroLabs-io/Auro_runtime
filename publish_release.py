"""Publish artifacts that a release-evidence record already vouches for.

This module is operator-facing release infrastructure and is deliberately not
registered as a runtime tool, for the same reason ``release_evidence.py`` is not:
a model must not be able to publish, nor to choose what gets published.

The division of labour matters.  ``release_evidence.py`` builds a candidate from
one named commit and proves it.  This command publishes a candidate somebody
already proved, and **it cannot build anything**: there is no call to ``build``
here, no source tree is read, and the only files it can upload are the ones a
record names.  Required-gate item 8 -- *publish only the already-tested
artifacts, not rebuild them during upload* -- is enforced by the absence of a
build path rather than by remembering not to take one.

It is also the first reader the evidence record has ever had.  Until now nothing
consumed ``release-evidence.json``: ``release_complete`` was computed, written,
retained, and never checked by anything, which made it a transcript rather than a
control.  Refusing to publish a record that says ``false`` is what gives the
field a consequence, and the same applies to ``publication_candidate`` -- an
assertion nothing acts on is an assertion nothing enforces.

Credentials are twine's business and never this script's.  Nothing here reads,
prints, stores, or accepts a token; ``twine`` resolves ``TWINE_USERNAME`` and
``TWINE_PASSWORD`` or ``~/.pypirc`` in its own process.  The operator supplies
them, and this command never sees them.

Law 3 -- fail closed by default -- shapes every gate below, and the sharpest
instance is ``--repository``, which has no default at all.  A default of
``pypi`` would make the irreversible destination the one you get by forgetting
to think; a default of ``testpypi`` would make a real release quietly land
somewhere nobody looks.  Neither valence is safe, so the argument is required
and the empty scope is refusal.

``--expected-commit`` is required for the same reason, and was optional until
2026-08-30.  A record proves *which* commit produced a candidate; only the
operator can say which commit this release is meant to be.  While the comparison
was opt-in, the two were never required to agree, so an older valid candidate --
a stale ``dist/`` or a CI artifact from last week -- cleared every gate in this
file and would have uploaded.  Omission permitted rather than refused, which is
the exact valence law 3b asks every empty scope to declare.  The record's commit
is now compared against operator intent on every run, and the comparison cannot
be skipped by leaving an argument out.

The other thing a record cannot be trusted to do is name a path.  It names
*files in the evidence directory*, so every filename it carries must be an
immediate member of that directory: no separators in either platform's spelling,
no drive letters, no ``..``, and no symlinks in either direction.  A record
filename that resolves elsewhere would otherwise pass the size and digest checks
against a file the directory listing never saw, which makes the "no unnamed
artifact" direction unenforceable and the directory claim false.  Refusing the
shape is cheaper and more honest than resolving it: the trusted producer emits
``path.name`` and nothing legitimate needs the other cases.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Sequence


_EVIDENCE_FILENAME = "release-evidence.json"
_ARTIFACT_SUFFIXES = (".whl", ".tar.gz")

# The same shape ``release_evidence.py`` requires of its own --expected-commit.
# An abbreviation is refused rather than resolved: this command has no repository
# to resolve it against, and a prefix comparison would silently accept a shorter
# and shorter claim until it accepted anything.
_FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}")

# Named rather than free-form. A URL typed at the command line is a destination
# nobody reviewed, and the two that matter are both known in advance.
_REPOSITORIES = {
    "testpypi": "https://test.pypi.org/legacy/",
    "pypi": "https://upload.pypi.org/legacy/",
}


class PublishError(RuntimeError):
    """The requested upload could not be tied to a record that vouches for it."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_evidence(evidence_dir: Path) -> dict:
    """Read the record, or refuse.

    A directory holding artifacts and no record is the case worth being explicit
    about: it looks exactly like a successful build, and it is precisely the
    state this command exists to refuse to publish.
    """
    record_path = evidence_dir / _EVIDENCE_FILENAME
    if not record_path.is_file():
        raise PublishError(
            f"no {_EVIDENCE_FILENAME} in {evidence_dir}; there is nothing "
            "vouching for these files and this command will not vouch for them"
        )
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublishError(f"{record_path} could not be read as JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise PublishError(f"{record_path} does not contain a JSON object")
    return record


def verify_record_permits_publication(
    record: dict,
    expected_commit: str,
) -> None:
    """Check what the record says about itself before checking the files.

    Ordering is deliberate: a record that never claimed to be publishable should
    be refused on that ground, with that reason, rather than on a digest
    mismatch discovered afterwards.  The clearer refusal is the one that names
    the actual disqualification.

    ``expected_commit`` has no default.  It is the operator's statement of which
    commit this release is, and there is no safe value to supply on their behalf:
    the record's own commit would make the comparison tautological, and any other
    would be invented.  Passing ``None`` is refused here as well as at the
    parser, so a caller inside this repository cannot re-open the hole the
    command line no longer has.
    """
    if record.get("release_complete") is not True:
        raise PublishError(
            "record does not assert release_complete; a candidate whose own "
            "gates did not all pass is not publishable"
        )

    source = record.get("source")
    if not isinstance(source, dict):
        raise PublishError("record carries no source identity")

    if source.get("publication_candidate") is not True:
        ref = source.get("ref")
        raise PublishError(
            "record was not asserted as a publication candidate "
            f"(ref={ref!r}); it is evidence for a tree, not a release. "
            "Rebuild with --publication-candidate if this ref really is one "
            "the project publishes from"
        )

    commit = source.get("commit")
    if not isinstance(commit, str) or not commit:
        raise PublishError("record names no commit")

    if not isinstance(expected_commit, str) or _FULL_COMMIT.fullmatch(expected_commit) is None:
        raise PublishError(
            "--expected-commit must be the full 40-character Git object id of "
            "the commit this release is meant to be; it is required, and an "
            f"abbreviation is not accepted (got {expected_commit!r})"
        )

    if commit.lower() != expected_commit.lower():
        raise PublishError(
            f"record is for commit {commit}, but --expected-commit says "
            f"{expected_commit.lower()}"
        )


def _contained_member(evidence_dir: Path, filename: str) -> Path:
    """Join a record-supplied filename onto the evidence directory, or refuse.

    The check is on the *shape* of the name, before the filesystem is consulted,
    because the filesystem is what the escaping cases are trying to reach.  Both
    path flavours are asked, not the running platform's: a record written on
    Linux is consumed on Windows and the reverse, and each flavour recognises a
    separator the other reads as an ordinary character.  ``PureWindowsPath``
    catches ``a\\b`` and the drive-relative ``C:x``; ``PurePosixPath`` catches
    ``a/b``.  ``.``, ``..`` and ``/abs/x`` all fail the same equality, since
    none of them is its own basename.

    The resolved-parent check afterwards is not redundant with it.  The shape
    check says the name cannot describe a path out of the directory; the parent
    check says the object it actually landed on is in the directory, which is a
    different claim once symlinks exist -- law 10, where validation and action
    must agree on what the input means.
    """
    if not filename:
        raise PublishError("record names an artifact with an empty filename")
    if (
        PurePosixPath(filename).name != filename
        or PureWindowsPath(filename).name != filename
    ):
        raise PublishError(
            f"record names {filename!r}, which is not an immediate member of "
            f"{evidence_dir}. A record names files in its own evidence "
            "directory, never paths to anywhere else"
        )

    path = evidence_dir / filename
    if path.is_symlink():
        raise PublishError(
            f"{filename} is a symbolic link. The record vouches for bytes in "
            f"{evidence_dir}, and a link's bytes are chosen by its target, "
            "which can change between this check and the upload"
        )
    if path.exists() and path.resolve().parent != evidence_dir:
        raise PublishError(
            f"{filename} resolves to {path.resolve()}, which is outside "
            f"{evidence_dir}"
        )
    return path


def verify_artifacts_match_record(
    evidence_dir: Path,
    record: dict,
) -> list[Path]:
    """Every named file present and byte-identical, and no unnamed file beside them.

    Both directions are load-bearing, which is law 1c in the shape it takes here.
    Checking only that the named files match would publish a rebuilt wheel that
    happened to be dropped in alongside them; checking only the directory listing
    would not notice a file whose contents changed.  The close condition this
    serves says the uploaded files are byte-identical to the tested candidates,
    and an extra file is a file nobody tested.
    """
    evidence_dir = evidence_dir.resolve()
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise PublishError("record names no artifacts")

    named: dict[str, dict] = {}
    for entry in artifacts:
        if not isinstance(entry, dict) or not isinstance(entry.get("filename"), str):
            raise PublishError(f"malformed artifact entry in record: {entry!r}")
        named[entry["filename"]] = entry

    # A link is refused here too, and not merely skipped. `is_file()` follows
    # the link, so an unfiltered listing would compare the target's identity
    # while the upload would hand twine the link -- and a dangling one would
    # vanish from the listing entirely, which is the quiet direction: a file
    # nobody can read is not a file nobody put there.
    present: set[str] = set()
    for path in evidence_dir.iterdir():
        if not path.name.endswith(_ARTIFACT_SUFFIXES):
            continue
        if path.is_symlink():
            raise PublishError(
                f"{evidence_dir} holds a symbolic link named {path.name}. "
                "Nothing in an evidence directory may be a link: the bytes "
                "that were tested are the ones that must be uploaded"
            )
        if path.is_file():
            present.add(path.name)
    unnamed = present - named.keys()
    if unnamed:
        raise PublishError(
            f"{evidence_dir} holds artifacts the record does not name: "
            f"{sorted(unnamed)}. Nothing tested them, so nothing may publish them"
        )

    verified: list[Path] = []
    for filename, entry in sorted(named.items()):
        path = _contained_member(evidence_dir, filename)
        if not path.is_file():
            raise PublishError(f"record names {filename}, which is not in {evidence_dir}")

        expected_size = entry.get("size")
        actual_size = path.stat().st_size
        if isinstance(expected_size, int) and actual_size != expected_size:
            raise PublishError(
                f"{filename} is {actual_size} bytes; the record recorded "
                f"{expected_size}"
            )

        expected_digest = entry.get("sha256")
        if not isinstance(expected_digest, str) or not expected_digest:
            raise PublishError(f"record carries no sha256 for {filename}")
        actual_digest = _sha256(path)
        if actual_digest.lower() != expected_digest.lower():
            raise PublishError(
                f"{filename} does not match the record.\n"
                f"  recorded: {expected_digest.lower()}\n"
                f"  on disk:  {actual_digest}\n"
                "This file is not the one that was tested. Refusing rather than "
                "publishing it, and rebuilding here is not an option this "
                "command has"
            )
        verified.append(path)

    return verified


def publish(
    evidence_dir: Path,
    repository: str,
    expected_commit: str,
    dry_run: bool = False,
) -> list[Path]:
    """Run every gate, then hand the exact files to twine.

    ``dry_run`` stops after the last gate.  It exists so the whole mechanism can
    be exercised -- in tests, in CI, and by an operator rehearsing a release --
    without credentials, without network access, and without consuming a version
    number that can never be reused.  A gate that can only be tested by
    performing the irreversible act it guards is a gate nobody tests.
    """
    evidence_dir = evidence_dir.resolve()
    if not evidence_dir.is_dir():
        raise PublishError(f"not a directory: {evidence_dir}")
    if repository not in _REPOSITORIES:
        raise PublishError(
            f"unknown repository {repository!r}; expected one of "
            f"{sorted(_REPOSITORIES)}"
        )

    record = load_evidence(evidence_dir)
    verify_record_permits_publication(record, expected_commit)
    files = verify_artifacts_match_record(evidence_dir, record)

    source = record["source"]
    print(
        f"verified {len(files)} artifact(s) against {_EVIDENCE_FILENAME}\n"
        f"  commit: {source['commit']}\n"
        f"  intent: {expected_commit.lower()} (--expected-commit)\n"
        f"  ref:    {source.get('ref')!r}\n"
        f"  target: {repository} ({_REPOSITORIES[repository]})"
    )
    for path in files:
        print(f"  ok  {path.name}")

    if dry_run:
        print("\n--dry-run: every gate passed; stopping before upload.")
        return files

    # Exact paths, never a glob. A glob is evaluated against whatever is in the
    # directory at upload time, which is the one moment the verification above
    # stops being true.
    command = [
        sys.executable, "-B", "-m", "twine", "upload",
        "--repository-url", _REPOSITORIES[repository],
        *(str(path) for path in files),
    ]
    print(f"\nuploading to {repository} ...")
    # Credentials are resolved by twine from its own environment. They are not
    # read here, not passed on the command line where any process could see
    # them, and not logged.
    result = subprocess.run(command, cwd=evidence_dir, text=True, timeout=1800)
    if result.returncode != 0:
        raise PublishError(f"twine upload failed with exit code {result.returncode}")
    print(f"published {len(files)} artifact(s) to {repository}")
    return files


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish the artifacts a release-evidence record vouches for. "
            "Builds nothing and verifies every file against the record first."
        )
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path("dist"),
        help=(
            "directory holding the wheel, the sdist and release-evidence.json, "
            "as produced by release_evidence.py or retained by CI"
        ),
    )
    parser.add_argument(
        "--repository",
        required=True,
        choices=sorted(_REPOSITORIES),
        help=(
            "where to publish. Required and has no default: neither possible "
            "default is safe to get by forgetting to choose"
        ),
    )
    parser.add_argument(
        "--expected-commit",
        required=True,
        help=(
            "full 40-character id of the commit this release is meant to be. "
            "Required: the record proves which commit produced these files, "
            "and only you can say which commit was intended, so a stale but "
            "valid candidate cannot be published in place of it"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run every gate and stop before uploading anything",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        publish(args.evidence_dir, args.repository, args.expected_commit, args.dry_run)
    except PublishError as exc:
        print(f"publication refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
