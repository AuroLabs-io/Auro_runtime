"""Coverage for the publication gate.

Written alongside `publish_release.py` rather than after it, because the sibling
gate's own card records what happens otherwise: no test imports or calls
`build_release_evidence`, and its eight refusal strings return zero grep hits
across `tests/`, so deleting the tar-containment pre-check would stay green on
all nine CI jobs. Correct code with unguarded correctness is one edit from being
incorrect code that still looks fine.

Law 15 is the law this module exists to serve -- a signal produced and never
consumed is indistinguishable from one never produced. Until `publish_release.py`
nothing had ever read `release-evidence.json` back: `release_complete` and
`publication_candidate` were computed, written, retained by CI, and consumed by
nothing at all. A field nobody reads cannot refuse anything, which is why the
record was a transcript. These tests pin the reading.

Law 1c shapes the structure: every guard gets a case where it fires and the
suite gets a case where none of them do. A file of refusals that never shows the
happy path passing is consistent with a gate that refuses everything, which
would be a different defect wearing the same green.

Deliberately fast: the gate cares only whether bytes match a record, never what
the bytes mean, so these use small synthetic artifacts and no wheel build. The
real artifacts are exercised by the distribution matrix.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from publish_release import (
    PublishError,
    load_evidence,
    publish,
    verify_artifacts_match_record,
    verify_record_permits_publication,
)


_COMMIT = "f324df6062c6a14868909a4fd59fee603e1e9bec"
_WHEEL = "auro_runtime-0.1.0-py3-none-any.whl"
_SDIST = "auro_runtime-0.1.0.tar.gz"


def _write_candidate(directory: Path, **record_overrides) -> dict:
    """A directory that looks exactly like a verified candidate, plus overrides."""
    directory.mkdir(parents=True, exist_ok=True)
    artifacts = []
    for name, body in ((_WHEEL, b"wheel-bytes"), (_SDIST, b"sdist-bytes")):
        path = directory / name
        path.write_bytes(body)
        artifacts.append(
            {
                "filename": name,
                "size": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )

    record = {
        "schema_version": 1,
        "artifacts": artifacts,
        "release_complete": True,
        "source": {
            "commit": _COMMIT,
            "ref": "refs/heads/main",
            "publication_candidate": True,
            "status": "clean",
        },
    }
    record.update(record_overrides)
    (directory / "release-evidence.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    return record


class TestTheGateLetsAGoodCandidateThrough:
    """Law 1: refusals prove nothing unless something is also allowed to pass."""

    def test_a_verified_candidate_passes_every_gate(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path)
        files = publish(tmp_path, "testpypi", dry_run=True)
        assert sorted(path.name for path in files) == sorted([_SDIST, _WHEEL])

    def test_the_expected_commit_check_passes_on_the_right_commit(
        self, tmp_path: Path
    ) -> None:
        _write_candidate(tmp_path)
        files = publish(tmp_path, "testpypi", expected_commit=_COMMIT, dry_run=True)
        assert len(files) == 2


class TestTheRecordMustVouchForTheUpload:
    """The half that was a transcript until something read it (law 15)."""

    def test_a_directory_with_no_record_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path)
        (tmp_path / "release-evidence.json").unlink()
        with pytest.raises(PublishError, match="nothing vouching for these files"):
            publish(tmp_path, "testpypi", dry_run=True)

    def test_an_incomplete_release_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path, release_complete=False)
        with pytest.raises(PublishError, match="release_complete"):
            publish(tmp_path, "testpypi", dry_run=True)

    def test_a_candidate_nobody_asserted_as_publishable_is_refused(
        self, tmp_path: Path
    ) -> None:
        """The first consequence `publication_candidate` has ever carried.

        Its own card records the field as materially weaker than it looks; this
        does not fix that guard, but it means a record that fails it can no
        longer be published by this path.
        """
        record = _write_candidate(tmp_path)
        record["source"]["publication_candidate"] = False
        (tmp_path / "release-evidence.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        with pytest.raises(PublishError, match="not asserted as a publication candidate"):
            publish(tmp_path, "testpypi", dry_run=True)

    def test_a_record_for_a_different_commit_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path)
        with pytest.raises(PublishError, match="--expected-commit"):
            publish(tmp_path, "testpypi", expected_commit="0" * 40, dry_run=True)

    def test_a_record_that_is_not_json_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path)
        (tmp_path / "release-evidence.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(PublishError, match="could not be read as JSON"):
            load_evidence(tmp_path)


class TestTheFilesMustBeTheOnesThatWereTested:
    """Byte-identity in both directions, which is the close condition's wording."""

    def test_a_tampered_artifact_of_the_same_length_is_refused(
        self, tmp_path: Path
    ) -> None:
        """Same length, different bytes -- the case only the digest can catch.

        The size check runs first and would shadow this one for any tamper that
        changes the length, so the substitution here is byte-for-byte. That is
        also the adversarial shape: a replacement crafted to pass a cheaper
        check is the reason the expensive one exists.
        """
        _write_candidate(tmp_path)
        original = (tmp_path / _WHEEL).read_bytes()
        tampered = b"wheel-bytez"
        assert len(tampered) == len(original), "the tamper must not change the size"
        (tmp_path / _WHEEL).write_bytes(tampered)
        with pytest.raises(PublishError, match="does not match the record"):
            publish(tmp_path, "testpypi", dry_run=True)

    def test_an_artifact_of_the_wrong_size_is_refused(self, tmp_path: Path) -> None:
        record = _write_candidate(tmp_path)
        record["artifacts"][0]["size"] = 999999
        (tmp_path / "release-evidence.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        with pytest.raises(PublishError, match="bytes; the record recorded"):
            publish(tmp_path, "testpypi", dry_run=True)

    def test_a_missing_artifact_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path)
        (tmp_path / _SDIST).unlink()
        with pytest.raises(PublishError, match="which is not in"):
            publish(tmp_path, "testpypi", dry_run=True)

    def test_an_artifact_the_record_does_not_name_is_refused(
        self, tmp_path: Path
    ) -> None:
        """The direction that catches a rebuild dropped in beside the tested files.

        Verifying only the named files would publish this happily: every named
        file still matches. What makes it a defect is the file nobody tested
        travelling with them.
        """
        _write_candidate(tmp_path)
        (tmp_path / "auro_runtime-0.1.0-py3-none-any-REBUILT.whl").write_bytes(b"x")
        with pytest.raises(PublishError, match="the record does not name"):
            publish(tmp_path, "testpypi", dry_run=True)

    def test_a_record_naming_no_artifacts_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path, artifacts=[])
        with pytest.raises(PublishError, match="names no artifacts"):
            publish(tmp_path, "testpypi", dry_run=True)


class TestTheDestinationIsNeverImplicit:
    """Law 3, in the one place where neither possible default is the safe one."""

    def test_an_unknown_repository_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path)
        with pytest.raises(PublishError, match="unknown repository"):
            publish(tmp_path, "not-a-repository", dry_run=True)

    def test_the_parser_requires_a_repository(self) -> None:
        """No default means forgetting to choose cannot pick the irreversible one."""
        from publish_release import _parser

        with pytest.raises(SystemExit):
            _parser().parse_args(["--evidence-dir", "dist"])


class TestTheGuardsAreLoadBearing:
    """Law 1c: each helper must refuse when its own subject is wrong.

    Calling the helpers directly rather than through `publish` so that a failure
    names the guard that stopped firing, instead of reporting that some earlier
    gate happened to catch it first.
    """

    def test_record_verification_rejects_each_disqualification(self) -> None:
        good = {
            "release_complete": True,
            "source": {"commit": _COMMIT, "publication_candidate": True},
        }
        verify_record_permits_publication(good)  # the anchor: this one must pass

        for mutation, expected in [
            ({"release_complete": False}, "release_complete"),
            ({"source": {"commit": _COMMIT, "publication_candidate": False}},
             "not asserted as a publication candidate"),
            ({"source": {"publication_candidate": True}}, "names no commit"),
            ({"source": "not-a-dict"}, "no source identity"),
        ]:
            record = {**good, **mutation}
            with pytest.raises(PublishError, match=expected):
                verify_record_permits_publication(record)

    def test_artifact_verification_needs_both_directions(self, tmp_path: Path) -> None:
        record = _write_candidate(tmp_path)
        assert len(verify_artifacts_match_record(tmp_path, record)) == 2

        (tmp_path / "stowaway.whl").write_bytes(b"never tested")
        with pytest.raises(PublishError, match="does not name"):
            verify_artifacts_match_record(tmp_path, record)
