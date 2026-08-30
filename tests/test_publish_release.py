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
    _contained_member,
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
        files = publish(tmp_path, "testpypi", _COMMIT, dry_run=True)
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
            publish(tmp_path, "testpypi", _COMMIT, dry_run=True)

    def test_an_incomplete_release_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path, release_complete=False)
        with pytest.raises(PublishError, match="release_complete"):
            publish(tmp_path, "testpypi", _COMMIT, dry_run=True)

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
            publish(tmp_path, "testpypi", _COMMIT, dry_run=True)

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
            publish(tmp_path, "testpypi", _COMMIT, dry_run=True)

    def test_an_artifact_of_the_wrong_size_is_refused(self, tmp_path: Path) -> None:
        record = _write_candidate(tmp_path)
        record["artifacts"][0]["size"] = 999999
        (tmp_path / "release-evidence.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        with pytest.raises(PublishError, match="bytes; the record recorded"):
            publish(tmp_path, "testpypi", _COMMIT, dry_run=True)

    def test_a_missing_artifact_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path)
        (tmp_path / _SDIST).unlink()
        with pytest.raises(PublishError, match="which is not in"):
            publish(tmp_path, "testpypi", _COMMIT, dry_run=True)

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
            publish(tmp_path, "testpypi", _COMMIT, dry_run=True)

    def test_a_record_naming_no_artifacts_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path, artifacts=[])
        with pytest.raises(PublishError, match="names no artifacts"):
            publish(tmp_path, "testpypi", _COMMIT, dry_run=True)


class TestTheDestinationIsNeverImplicit:
    """Law 3, in the one place where neither possible default is the safe one."""

    def test_an_unknown_repository_is_refused(self, tmp_path: Path) -> None:
        _write_candidate(tmp_path)
        with pytest.raises(PublishError, match="unknown repository"):
            publish(tmp_path, "not-a-repository", _COMMIT, dry_run=True)

    def test_the_parser_requires_a_repository(self) -> None:
        """No default means forgetting to choose cannot pick the irreversible one.

        Every other argument is supplied, so the exit can only be the missing
        repository. Omitting two required arguments and observing one exit would
        prove nothing about either -- and this test did exactly that for a day
        after `--expected-commit` became required.
        """
        from publish_release import _parser

        with pytest.raises(SystemExit):
            _parser().parse_args(
                ["--evidence-dir", "dist", "--expected-commit", _COMMIT]
            )

    def test_the_parser_requires_an_expected_commit(self) -> None:
        """The argument whose absence used to be a pass.

        Same construction as the repository case above and for the same reason:
        the repository is supplied, so the exit is attributable to the commit.
        """
        from publish_release import _parser

        with pytest.raises(SystemExit):
            _parser().parse_args(
                ["--evidence-dir", "dist", "--repository", "testpypi"]
            )

    def test_the_documented_command_satisfies_the_parser(self) -> None:
        """The README shows a command; this runs its arguments through the parser.

        A documented example is a claim about what works, and prose has no
        failing event -- it drifts instead of breaking. This one drifted in
        exactly that way: `--expected-commit` was added to the tool and the
        example kept working without it, so the documented path was the one
        that skipped the check. Parsing the example means the docs cannot go
        stale in the direction that matters, because the parser's required set
        and the example are now checked against each other.

        It does not prove the command succeeds -- that needs a real candidate,
        and the release gate is where that lives. It proves the documented
        arguments are the ones this tool actually requires.
        """
        import re
        import shlex

        from publish_release import _parser

        readme = Path(__file__).resolve().parents[1] / "README.md"
        text = readme.read_text(encoding="utf-8").replace("\r\n", "\n")
        blocks = re.findall(r"```bash\n(.*?)```", text, re.DOTALL)
        documented = [block for block in blocks if "publish_release.py" in block]
        assert len(documented) == 1, (
            f"expected exactly one documented publish command, found {len(documented)}"
        )

        tokens = shlex.split(documented[0].replace("\\\n", " "))
        assert tokens[:3] == ["python", "-B", "publish_release.py"], tokens[:3]
        args = _parser().parse_args(tokens[3:])

        assert args.expected_commit, "the documented command omits --expected-commit"
        assert args.repository == "testpypi", (
            "the documented rehearsal must name the test index, not the real one"
        )
        assert args.dry_run is True, "the documented command must be the rehearsal"

    def test_the_parser_accepts_the_complete_command(self) -> None:
        """The anchor: with all three supplied, nothing exits.

        Without this, both tests above are consistent with a parser that refuses
        every invocation.
        """
        from publish_release import _parser

        args = _parser().parse_args(
            [
                "--evidence-dir", "dist",
                "--repository", "testpypi",
                "--expected-commit", _COMMIT,
                "--dry-run",
            ]
        )
        assert args.expected_commit == _COMMIT
        assert args.repository == "testpypi"
        assert args.dry_run is True


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
        # the anchor: this one must pass
        verify_record_permits_publication(good, _COMMIT)

        for mutation, expected in [
            ({"release_complete": False}, "release_complete"),
            ({"source": {"commit": _COMMIT, "publication_candidate": False}},
             "not asserted as a publication candidate"),
            ({"source": {"publication_candidate": True}}, "names no commit"),
            ({"source": "not-a-dict"}, "no source identity"),
        ]:
            record = {**good, **mutation}
            with pytest.raises(PublishError, match=expected):
                verify_record_permits_publication(record, _COMMIT)

    def test_artifact_verification_needs_both_directions(self, tmp_path: Path) -> None:
        record = _write_candidate(tmp_path)
        assert len(verify_artifacts_match_record(tmp_path, record)) == 2

        (tmp_path / "stowaway.whl").write_bytes(b"never tested")
        with pytest.raises(PublishError, match="does not name"):
            verify_artifacts_match_record(tmp_path, record)


class TestTheRecordMustAgreeWithReleaseIntent:
    """`--expected-commit` was optional until 2026-08-30, and omission permitted.

    The record proves which commit produced a candidate. Nothing in it can say
    which commit the operator meant to release, so while the comparison was
    opt-in the two were never required to agree. These pin the comparison
    happening on every path, since the defect was never that the check was
    wrong -- supplied, it always worked -- but that it could be skipped.
    """

    def test_a_stale_but_valid_candidate_is_refused(self, tmp_path: Path) -> None:
        """The 2026-08-29 audit's finding, reproduced rather than cited.

        Every gate in this file passes on this directory: the record asserts
        release_complete and publication_candidate, both artifacts are present,
        the right size, and hash correctly. It is a perfectly good candidate for
        a commit that is not the one being released.
        """
        _write_candidate(tmp_path)
        with pytest.raises(PublishError, match="--expected-commit says"):
            publish(tmp_path, "testpypi", "a" * 40, dry_run=True)

    def test_an_absent_intent_cannot_reach_the_gates(self, tmp_path: Path) -> None:
        """Defence in depth behind the parser, for callers inside this repo.

        `--expected-commit` is `required=True`, so the command line cannot omit
        it. This is the other door: a caller in-process passing None must be
        refused rather than falling through to the old optional behaviour.
        """
        _write_candidate(tmp_path)
        with pytest.raises(PublishError, match="must be the full 40-character"):
            publish(tmp_path, "testpypi", None, dry_run=True)  # type: ignore[arg-type]

    def test_an_abbreviation_is_refused_rather_than_resolved(
        self, tmp_path: Path
    ) -> None:
        """A prefix comparison would accept a shorter claim each time it is asked.

        This command has no repository to resolve an abbreviation against, so
        the only two options are refusing it and comparing prefixes. The second
        is how `--expected-commit ""` would come to mean "anything".
        """
        _write_candidate(tmp_path)
        for abbreviation in (_COMMIT[:7], _COMMIT[:12], _COMMIT[:39], "", "not-hex"):
            with pytest.raises(PublishError, match="full 40-character"):
                publish(tmp_path, "testpypi", abbreviation, dry_run=True)

    def test_the_comparison_is_case_insensitive(self, tmp_path: Path) -> None:
        """Git object ids are hex; an operator pasting upper case meant the same commit."""
        _write_candidate(tmp_path)
        files = publish(tmp_path, "testpypi", _COMMIT.upper(), dry_run=True)
        assert len(files) == 2


class TestARecordNamesFilesNotPathsToElsewhere:
    """The record's filenames must be immediate members of the evidence directory.

    Law 10 in the shape it takes here: `verify_artifacts_match_record` listed the
    directory to decide what was unnamed, then joined record-supplied names onto
    that directory to decide what to publish. The two steps did not have to be
    talking about the same set of files, and a name carrying a separator is
    exactly the input that separates them.
    """

    def test_an_artifact_outside_the_directory_is_refused(self, tmp_path: Path) -> None:
        """The audit's second finding, reproduced end to end.

        The smuggled file is byte-identical to the tested wheel, so size and
        digest both pass; the directory listing shows nothing unnamed, because
        the wheel is no longer in it. Everything the record can assert about
        bytes is true. The only thing wrong is where the bytes are, which is the
        one thing the old code did not check.
        """
        evidence = tmp_path / "evidence"
        record = _write_candidate(evidence)
        outside = tmp_path / "sibling"
        outside.mkdir()
        (outside / _WHEEL).write_bytes((evidence / _WHEEL).read_bytes())
        (evidence / _WHEEL).unlink()

        record["artifacts"][0]["filename"] = f"../sibling/{_WHEEL}"
        (evidence / "release-evidence.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        with pytest.raises(PublishError, match="not an immediate member"):
            publish(evidence, "testpypi", _COMMIT, dry_run=True)

    def test_every_escaping_shape_is_refused(self, tmp_path: Path) -> None:
        """Both platforms' separators, on whichever platform is running.

        A record written by CI on Linux is read by an operator on Windows and
        the reverse, and each flavour reads the other's separator as an ordinary
        filename character. Asking only the running platform would leave one
        spelling open on each -- law 7b, the input shapes rather than the call
        sites.
        """
        anchor = _contained_member(tmp_path, _WHEEL)
        assert anchor == tmp_path / _WHEEL, "the ordinary case must still pass"

        for filename in (
            "../outside.whl",
            "..\\outside.whl",
            "sub/inner.whl",
            "sub\\inner.whl",
            "/abs/outside.whl",
            "C:\\outside.whl",
            "C:outside.whl",
            "..",
            ".",
            "",
        ):
            with pytest.raises(PublishError):
                _contained_member(tmp_path, filename)

    def test_a_named_artifact_that_is_a_link_is_refused(self, tmp_path: Path) -> None:
        """Decided policy: no symlinks in an evidence directory, either direction.

        A link's bytes are chosen by its target, which can change between the
        digest check and the upload; and the containment argument above is only
        as good as the assumption that a contained name is a contained file.
        Refusing costs nothing, because `release_evidence.py` writes regular
        files. Skipped where the account cannot create links -- the ubuntu CI
        legs run it, and a skip is not a pass.

        Deliberately calling `_contained_member` rather than `publish`. There
        are two symlink refusals -- this one, and the directory listing's -- and
        going through `publish` hits the listing first, so this test passed with
        this guard removed. Two enforcement points behind one observable are one
        control to any test that cannot tell them apart, so each gets a test
        that fails when it alone is gone.
        """
        evidence = tmp_path / "evidence"
        _write_candidate(evidence)
        target = tmp_path / "elsewhere.whl"
        target.write_bytes((evidence / _WHEEL).read_bytes())
        (evidence / _WHEEL).unlink()
        try:
            (evidence / _WHEEL).symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"this platform or account cannot create symlinks: {exc}")

        with pytest.raises(PublishError, match="is a symbolic link"):
            _contained_member(evidence, _WHEEL)

    def test_a_link_beside_the_artifacts_is_refused(self, tmp_path: Path) -> None:
        """The listing's own refusal, on a link the record never names.

        `is_file()` follows a link, so an unfiltered listing compares the
        target's identity while the upload would hand twine the link. A dangling
        one is worse: it disappears from the listing entirely, and a file nobody
        can read is not a file nobody put there.
        """
        evidence = tmp_path / "evidence"
        _write_candidate(evidence)
        try:
            (evidence / "stowaway.whl").symlink_to(tmp_path / "nowhere.whl")
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"this platform or account cannot create symlinks: {exc}")

        with pytest.raises(PublishError, match="holds a symbolic link"):
            publish(evidence, "testpypi", _COMMIT, dry_run=True)
