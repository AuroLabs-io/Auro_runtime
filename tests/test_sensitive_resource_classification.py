"""
The shared sensitive-resource classifier, and both layers that consume it.

Until 2026-08-18 the knowledge of "which paths name a credential" existed three
times -- in the policy guard, in the file tool's read path, and in the
pre-commit staged-file check -- with nothing keeping the copies in agreement.
This file covers the single definition that replaced them and the two properties
that make the pair of enforcement layers worth having:

  * both layers consult the same inventory, so a family added once is refused
    everywhere rather than in whichever module the author happened to edit; and
  * the layers obtain their subject differently on purpose. The guard judges the
    caller's string before anything is resolved; the tool judges the path the
    filesystem will actually open. Sharing the inventory is the fix; sharing the
    subject would rebuild the defect, because on 2026-08-16 both layers compared
    a raw model-supplied string and one trailing space opened both at once.

Every case here is a fact about this repository's own inventory and
normalisation -- which families it holds, which non-secrets it must not refuse.
"""

import json
import os
from pathlib import Path

import pytest

from auro_runtime.sensitive_paths import (
    UNCONTAINED,
    canonicalize_path,
    classify_resolved,
    classify_text,
    classify_workspace_relative,
)
from runtime_tools import file_tools
from runtime_tools.file_tools import delete_file, read_file, restore_file, write_file
from runtime_tools.validate_directive_tools import validate_directive


@pytest.fixture
def workspace_probe(repo_root: Path):
    """
    Plant a real file under the workspace root and remove it afterwards.

    The tools resolve against the frozen workspace root, so a test that drives
    read_file end-to-end needs its subject to exist there rather than in tmp_path.
    Removes exactly what it created -- the file, and any directory it had to
    create to hold it, only while still empty -- even when the test fails.
    """
    created_files: list[Path] = []
    created_dirs: list[Path] = []

    def _make(rel_path: str, content: str = "auro test probe -- safe to delete\n") -> str:
        target = (repo_root / rel_path).resolve()
        assert repo_root in target.parents, (
            f"refusing to write outside the repo root: {rel_path!r}"
        )
        probe_dir = target.parent
        while not probe_dir.exists():
            created_dirs.append(probe_dir)
            probe_dir = probe_dir.parent
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        created_files.append(target)
        return rel_path

    yield _make

    for f in created_files:
        f.unlink(missing_ok=True)
    for d in sorted(created_dirs, key=lambda p: len(p.parts), reverse=True):
        if d.is_dir() and not any(d.iterdir()):
            d.rmdir()


@pytest.fixture(autouse=True)
def archive_probe():
    """Restore `.auro_archive/` to exactly the state each test found it in.

    Autouse deliberately. Only some tests touch the archive, but which ones is
    not knowable in advance: a regression in any refusal turns a tool that was
    supposed to decline into one that archives a file, and the debris then
    breaks a later test's baseline rather than the failing one's. Relying on
    each author to remember the fixture is the same hand-maintained-list
    problem this suite exists to close.

    `.auro_archive/manifest.jsonl` is append-only and shared, so a test that
    writes a row must put the file back exactly as it found it -- including the
    case where it did not exist at all -- or it leaves a ledger row for an
    archive blob that is gone.
    """
    archive_dir = file_tools._get_archive_dir()
    manifest = archive_dir / "manifest.jsonl"
    before = manifest.read_text(encoding="utf-8") if manifest.exists() else None
    existing = {p.name for p in archive_dir.iterdir()} if archive_dir.is_dir() else set()

    def _register(archive_name: str) -> str:
        return archive_name

    yield _register

    # Snapshot-and-restore rather than removing registered names. Under a
    # mutation that disables the classification, delete_file succeeds and
    # archives the file under a timestamped name the test never learns, so a
    # register-by-name fixture cannot clean it and the debris then breaks the
    # *next* mutation's control run. Removing whatever is new is robust to the
    # tool under test actually working.
    if archive_dir.is_dir():
        for p in archive_dir.iterdir():
            if p.name not in existing:
                p.unlink(missing_ok=True)
    if before is None:
        manifest.unlink(missing_ok=True)
    else:
        manifest.write_text(before, encoding="utf-8")
    if archive_dir.is_dir() and not any(archive_dir.iterdir()):
        archive_dir.rmdir()


class TestTheInventoryIsSharedNotCopied:
    """The deduplication's whole point: one list, every consumer."""

    def test_the_guard_and_the_read_path_agree_on_every_family(self):
        """
        The defect this replaced was three lists disagreeing silently. The guard
        held eleven patterns; the read path held three literal names. A family
        in the guard but not the tool was blocked before execution and readable
        once execution began.

        Asserting both entry points agree across the inventory is the property
        that made those copies wrong, so it is the property worth pinning.
        """
        families = [
            ".env", "auro_secrets.yaml", ".auro_secrets.yaml", ".htpasswd",
            "credentials.json", ".credentials", "id_rsa", "id_ed25519",
            ".ssh/config", ".aws/credentials", ".gnupg/secring.gpg",
        ]
        for name in families:
            by_guard = classify_text(name)
            by_tool = classify_workspace_relative(name)
            assert (by_guard is None) == (by_tool is None), (
                f"{name!r} is classified by one layer and not the other: "
                f"guard={by_guard}, tool={by_tool}"
            )
            assert by_guard.category == by_tool.category, (
                f"{name!r} is classified as {by_guard.category} by the guard and "
                f"{by_tool.category} by the tool -- the categories reach the "
                f"audit record, so they cannot disagree"
            )

    @pytest.mark.parametrize("name,category", [
        (".env", "env_file"),
        (".ssh/id_rsa", "ssh_key"),
        ("id_ed25519", "ssh_key"),
        (".aws/credentials", "cloud_credential"),
        (".gnupg/secring.gpg", "gpg_keyring"),
        ("auro_secrets.yaml", "auro_secret"),
        (".htpasswd", "web_auth"),
        ("credentials.json", "generic_credential"),
    ])
    def test_every_family_reports_its_category(self, name, category):
        """
        Categories exist because they reach the audit record. "Which class of
        secret was this" is what an operator can act on; "which regex matched"
        is an implementation detail that changes whenever the list is
        restructured, and an audit trail that reports it ages badly.
        """
        match = classify_text(name)
        assert match is not None, f"{name!r} was not classified at all"
        assert match.category == category


class TestTheResolvedSubjectIsWiderThanTheBasename:
    """What consuming the shared inventory added to the tool's read path.

    The deleted local list compared basenames. A file inside a credential
    directory whose own name is unremarkable -- `.ssh/config`, `.aws/cfg` --
    therefore passed the tool's own check entirely, and was refused only by the
    guard, which is the layer a resolution difference can slip past. Classifying
    the resolved relative path closes that.
    """

    @pytest.mark.parametrize("rel", [
        ".ssh/config",
        ".ssh/known_hosts",
        ".aws/cfg",
        ".gnupg/random_seed",
        "nested/dir/.ssh/config",
    ])
    def test_a_plain_name_inside_a_credential_directory_is_classified(self, rel):
        from pathlib import Path

        assert classify_workspace_relative(rel) is not None, (
            f"{rel!r} was not classified; the basename {Path(rel).name!r} is "
            f"unremarkable, which is exactly why judging the basename alone "
            f"was not enough"
        )

    @pytest.mark.parametrize("rel", [
        "output/config",
        "output/known_hosts",
        "docs/cfg",
        "notes/random_seed",
    ])
    def test_the_same_plain_names_outside_one_are_not(self, rel):
        """Control. Without this, classifying everything would pass above."""
        assert classify_workspace_relative(rel) is None, (
            f"{rel!r} is an ordinary file and was refused as a credential"
        )

    def test_read_file_refuses_a_plain_name_inside_a_credential_directory(
        self, workspace_probe
    ):
        """
        The property above, driven through the real tool rather than the
        classifier in isolation.

        `output/.ssh/config` is the discriminating case: its basename is
        `config`, which no pattern matches, so a read path judging the basename
        returns it happily. Only judging the resolved relative path refuses it.
        The file is planted on disk so the refusal cannot be mistaken for a
        missing-file error.
        """
        rel = workspace_probe("output/.ssh/config", "Host example\n")

        result = read_file(path=rel)

        assert "error" in result, f"{rel!r} was read: {result!r}"
        assert "blocked" in result["error"]
        assert "Host example" not in str(result)

    def test_read_file_still_returns_an_ordinary_neighbouring_file(
        self, workspace_probe
    ):
        """Control for the test above, in the same directory tree."""
        rel = workspace_probe("output/notes_probe.txt", "ordinary content\n")

        result = read_file(path=rel)

        assert "error" not in result, result
        assert "ordinary content" in result["content"]


class TestFilesystemAliasesAreResolvedBeforeClassification:
    """Aliases the string layer cannot see, and the resolved layer closes.

    Both cases below were measured on Windows 11 / NTFS on 2026-08-18 rather
    than reasoned about. In both, `Path.resolve()` returns the real target, so a
    layer classifying the resolved path refuses them while a layer classifying
    the caller's string does not -- which is the argument for the architecture,
    stated as a test rather than as a comment.
    """

    @pytest.mark.skipif(os.name != "nt", reason="NTFS alternate data streams")
    def test_an_alternate_data_stream_suffix_does_not_reach_file_contents(
        self, workspace_probe
    ):
        """
        `output/.env::$DATA` opens the real `output/.env` on NTFS. Measured
        against commit 19175eb, this returned the file's contents through both
        enforcement layers: the guard's patterns are `$`-anchored and `::$DATA`
        follows the anchor, and the tool compared a basename of `.env::$DATA`
        against a literal set. Same shape as the trailing-dot bypass of
        2026-08-16 and reachable the same way, with only read_file.
        """
        workspace_probe("output/.env", "AURO_TEST_PROBE_VALUE=xyz\n")

        result = read_file(path="output/.env::$DATA")

        assert "error" in result, f"the stream form was read: {result!r}"
        assert "AURO_TEST_PROBE_VALUE" not in str(result)

    @pytest.mark.parametrize("form", [
        "{base}/./.ssh/config",      # dot segment
        "{base}//.ssh/config",       # doubled separator
        "{base}/x/../.ssh/config",   # up and back
    ])
    def test_equivalent_spellings_all_resolve_to_the_same_subject(self, tmp_path, form):
        """Spellings the filesystem treats as one path must classify as one path.

        The `x/..` case needs `x` to be a real directory. POSIX resolves `..`
        against the actual directory it is in, so traversing through a
        non-existent component is ENOENT; Windows normalises the same string
        lexically and opens the file regardless. Without creating it, this
        passed on Windows and failed on every Linux runner -- caught by CI on
        2026-08-19, which is the difference between measuring one platform and
        measuring the supported ones.
        """
        base = tmp_path.resolve()
        ssh = base / ".ssh"
        ssh.mkdir()
        (ssh / "config").write_text("Host probe\n", encoding="utf-8")
        (base / "x").mkdir()

        candidate = Path(form.format(base=str(base).replace("\\", "/")))

        assert candidate.exists(), "the spelling must reach the real file to be a test"
        assert classify_resolved(candidate, base) is not None, (
            f"{candidate} reaches .ssh/config and was not classified"
        )

    @pytest.mark.skipif(os.name != "nt", reason="Windows extended-length prefix")
    def test_an_extended_length_path_fails_closed(self, tmp_path):
        r"""`\\?\C:\...` is NOT normalised by resolve(), and that is the point.

        Measured 2026-08-19: resolve() returns the prefix unchanged, so
        relative_to fails, so this classifier reports UNCONTAINED and refuses --
        and the tools' own `_path_under_base` refuses for the same reason. The
        form is therefore rejected rather than silently judged against a subject
        nobody relativised.

        Pinned because that outcome is currently *incidental*. If a future
        change teaches the resolution layer to strip the prefix, this form
        starts flowing through a path that was never designed for it, and
        nothing else would notice.
        """
        base = tmp_path.resolve()
        ssh = base / ".ssh"
        ssh.mkdir()
        (ssh / "config").write_text("Host probe\n", encoding="utf-8")

        extended = Path("\\\\?\\" + str(ssh / "config"))
        assert extended.exists(), "the prefix must still reach the file"

        match = classify_resolved(extended, base)
        assert match is not None, "an unrelativisable path was reported as clean"
        assert match.category == UNCONTAINED

    @pytest.mark.skipif(os.name != "nt", reason="NTFS 8.3 short names")
    def test_an_83_short_name_alias_is_expanded_before_classification(
        self, tmp_path
    ):
        """
        A short-name alias expands per existing component, so `SSH~1/anything`
        resolves into `.ssh/` even when the leaf does not exist. The string layer
        cannot catch this -- `SSH~1` matches no pattern and no amount of string
        normalisation makes it -- which is gap 3 of the resolved-resource card.

        Skipped rather than failed where 8.3 generation is off for the volume:
        the alias simply does not exist there, and asserting on an alias the
        filesystem never created would prove nothing either way.
        """
        import ctypes
        from ctypes import wintypes

        base = tmp_path.resolve()
        ssh = base / ".ssh"
        ssh.mkdir()
        (ssh / "config").write_text("Host probe\n", encoding="utf-8")

        get_short = ctypes.windll.kernel32.GetShortPathNameW
        get_short.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        get_short.restype = wintypes.DWORD
        buf = ctypes.create_unicode_buffer(1024)
        if not get_short(str(ssh), buf, 1024) or Path(buf.value) == ssh:
            pytest.skip("8.3 short-name generation is disabled for this volume")

        alias = Path(buf.value) / "config"
        assert classify_text(str(alias)) is None, (
            "this test is meaningless unless the string layer really is blind "
            "to the alias -- if it now catches it, the premise changed"
        )
        assert classify_resolved(alias, base) is not None, (
            f"{alias} resolves into .ssh/ and was not classified"
        )


class TestEveryMutatingToolClassifiesItsResolvedTarget:
    """The half a pre-execution guard structurally cannot reach.

    `check_sensitive_paths` inspects caller arguments. For `restore_file` with
    `restore_to` omitted there are no relevant caller arguments -- the
    destination is read out of the archive manifest -- so the guard finds
    nothing to look at and approves by having no opinion. Containment and
    writability were enforced; sensitivity was enforced by nobody.
    """

    @staticmethod
    def _plant_archive(rel_original: str, blob: str = "SECRET=probe\n") -> str:
        """Plant an archive entry and its manifest row without using delete_file.

        delete_file now classifies its target too, so a sensitive file cannot be
        archived through it. Archives predating this change, and those produced
        by `write_file` overwriting an existing file, still exist -- so planting
        the state directly is the faithful reproduction, not a contrivance.
        """
        archive_dir = file_tools._get_archive_dir()
        archive_dir.mkdir(parents=True, exist_ok=True)
        archive_name = "20260818_000000__" + "__".join(Path(rel_original).parts)
        (archive_dir / archive_name).write_text(blob, encoding="utf-8")
        manifest = archive_dir / "manifest.jsonl"
        with open(manifest, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "original_path": str(Path(rel_original)),
                "archive_path": archive_name,
                "deleted_at": "2026-08-18T00:00:00+00:00",
                "size_bytes": len(blob),
            }) + "\n")
        return archive_name

    def test_a_manifest_derived_destination_is_refused(self, archive_probe):
        """The card's gap 3, and the remaining ship blocker before this landed."""
        archive_name = archive_probe(
            self._plant_archive("output/.env", "SENTINEL_NOT_RESTORED=1\n")
        )

        result = restore_file(archive_name=archive_name)

        assert result.get("restored") is False, result
        assert "blocked" in result.get("error", "")
        # Assert the content was not materialised rather than that the path is
        # absent. A developer may legitimately have their own output/.env, and a
        # test that fails because of it is testing the machine, not the code.
        dest = file_tools._get_base_dir() / "output" / ".env"
        if dest.exists():
            assert "SENTINEL_NOT_RESTORED" not in dest.read_text(encoding="utf-8"), (
                "the destination was refused but the archived content was written anyway"
            )

    def test_an_ordinary_manifest_derived_destination_still_restores(
        self, archive_probe, workspace_probe
    ):
        """Positive control. Refusing everything would pass the test above."""
        workspace_probe("output/.keep", "hold the directory\n")
        archive_name = archive_probe(
            self._plant_archive("output/restored_notes.txt", "ordinary\n")
        )
        restored = file_tools._get_base_dir() / "output" / "restored_notes.txt"
        try:
            result = restore_file(archive_name=archive_name)
            assert result.get("restored") is True, result
            assert restored.read_text(encoding="utf-8") == "ordinary\n"
        finally:
            restored.unlink(missing_ok=True)

    def test_an_explicit_sensitive_restore_destination_is_refused(self, archive_probe):
        archive_name = archive_probe(
            self._plant_archive("output/restored_notes.txt", "ordinary\n")
        )

        result = restore_file(archive_name=archive_name, restore_to="output/.env")

        assert result.get("restored") is False, result
        assert "blocked" in result.get("error", "")

    def test_write_file_refuses_a_sensitive_destination(self):
        result = write_file(path="output/.env", content="SENTINEL_NOT_WRITTEN=1\n")

        assert result.get("written") is False, result
        assert "blocked" in result.get("error", "")
        dest = file_tools._get_base_dir() / "output" / ".env"
        if dest.exists():
            assert "SENTINEL_NOT_WRITTEN" not in dest.read_text(encoding="utf-8"), (
                "write_file reported a refusal and wrote the content anyway"
            )

    def test_write_file_still_writes_an_ordinary_neighbour(self):
        target = file_tools._get_base_dir() / "output" / "plain_probe.txt"
        try:
            result = write_file(path="output/plain_probe.txt", content="fine\n")
            assert result.get("written") is True, result
        finally:
            target.unlink(missing_ok=True)

    def test_delete_file_refuses_a_sensitive_target(self, workspace_probe):
        rel = workspace_probe("output/.env", "SECRET=probe\n")

        result = delete_file(path=rel)

        assert result.get("deleted") is False, result
        assert "blocked" in result.get("error", "")
        assert (file_tools._get_base_dir() / rel).exists(), (
            "the delete was refused but the file is gone"
        )


class TestValidateDirectiveClassifiesToo:
    """The fifth reader, and the one nothing else covers.

    The close condition says *every* filesystem tool submits its resolved target,
    and validate_directive reads a file. It is also the only one where the tool
    layer stands alone: the shipped `sensitive_paths` rule scopes to the five
    file tools and does not name it, so no policy guard runs for it at all.
    """

    def test_a_sensitive_md_file_is_refused(self, workspace_probe):
        """`.env.md` satisfies the .md requirement and is classified sensitive."""
        rel = workspace_probe("output/.env.md", "---\nid: x\n---\nbody\n")

        result = validate_directive(path=rel)

        assert result.get("valid") is False, result
        assert any("blocked" in e for e in result.get("errors", [])), result

    def test_an_ordinary_directive_still_validates(self, workspace_probe):
        """Positive control: the refusal must not swallow the tool's real job."""
        rel = workspace_probe(
            "output/probe_directive.md",
            "---\nid: probe_directive\ndescription: probe\ntools: [echo]\n---\n"
            "## Purpose\np\n## Steps\ns\n",
        )

        result = validate_directive(path=rel)

        assert "errors" in result
        assert not any("blocked" in e for e in result.get("errors", [])), result


class TestTheAuditDistinguishesApprovedFromNeverRan:
    """The close condition's evidence clause.

    Before this, a guard that approved returned None and wrote nothing, so an
    operator asking "was this control active during the incident" got the same
    silence whether it approved or never ran at all.
    """

    def test_an_approval_is_recorded(self, audit_events, workspace_probe):
        rel = workspace_probe("output/audited_probe.txt", "ordinary\n")

        read_file(path=rel)

        events = [e for e in audit_events if e.get("event") == "resource_classification"]
        assert len(events) == 1, events
        assert events[0]["outcome"] == "approved"
        assert events[0]["tool"] == "read_file"

    def test_a_refusal_is_recorded_with_its_category_and_origin(
        self, audit_events, archive_probe
    ):
        archive_name = archive_probe(self._plant())

        restore_file(archive_name=archive_name)

        events = [e for e in audit_events if e.get("event") == "resource_classification"]
        assert len(events) == 1, events
        assert events[0]["outcome"] == "refused"
        assert events[0]["category"] == "env_file"
        assert events[0]["origin"] == "manifest", (
            "the record must say the destination came from the manifest rather "
            "than from a caller argument -- that distinction is the finding"
        )
        assert events[0]["role"] == "destination"

    @staticmethod
    def _plant():
        return TestEveryMutatingToolClassifiesItsResolvedTarget._plant_archive("output/.env")

    def test_the_recorded_subject_is_workspace_relative(
        self, audit_events, workspace_probe
    ):
        """An absolute path carries the operator's directory layout off the box.

        `file_restored` was corrected for exactly this on 2026-08-08; a new
        event repeating it would reintroduce a closed defect.
        """
        rel = workspace_probe("output/audited_probe.txt", "ordinary\n")

        read_file(path=rel)

        event = next(e for e in audit_events if e.get("event") == "resource_classification")
        recorded = event["subjects"][0]["path"]
        assert recorded == "output/audited_probe.txt", recorded
        assert ":" not in recorded and not recorded.startswith("/")


class TestTheEnvSampleFamilyIsNoLongerRefused:
    """The false positive the inventory carried while it was three lists.

    `\\.env(\\..*)?$` refused the four canonical NON-secret files, whose whole
    purpose is to be read so a developer can discover which variables are
    required. At `enforcement: block` that refused a legitimate and common
    action, and a guard that cries wolf on the file people actually need teaches
    them to route around the guard.
    """

    @pytest.mark.parametrize("name", [
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        "config/.env.example",
        "output/.env.sample",
    ])
    def test_the_sample_family_is_permitted(self, name):
        assert classify_text(name) is None, f"{name!r} is a non-secret and was refused"

    @pytest.mark.parametrize("name", [
        ".env",
        ".env.production",
        ".env.local",
        "output/.env",
        # Named to look like the sample but carrying something else. The
        # exclusion requires the suffix to END the string, so this still fails.
        ".env.example.bak",
    ])
    def test_the_real_env_family_is_still_refused(self, name):
        """Control. Widening the exclusion until nothing matches would pass above."""
        assert classify_text(name) is not None, f"{name!r} is a secret and was allowed"

    def test_read_file_returns_an_env_example(self, workspace_probe):
        """End to end, because the refusal that mattered was at the tool."""
        rel = workspace_probe("output/.env.example", "API_KEY=\nDB_URL=\n")

        result = read_file(path=rel)

        assert "error" not in result, result
        assert "API_KEY=" in result["content"]

    def test_direnv_is_refused(self):
        """.envrc was matched by nothing: the old pattern needed a literal dot."""
        assert classify_text(".envrc") is not None


class TestTheAddedCredentialFamilies:

    @pytest.mark.parametrize("name,category", [
        (".netrc", "net_credential"),
        ("_netrc", "net_credential"),
        (".git-credentials", "vcs_credential"),
        (".kube/config", "orchestrator_credential"),
        ("etc/kubernetes/admin.conf", "orchestrator_credential"),
        (".vault-token", "secret_store"),
        ("run/secrets/db_password", "secret_store"),
        ("var/run/secrets/token", "secret_store"),
        (".pgpass", "db_credential"),
        (".my.cnf", "db_credential"),
        (".docker/config.json", "registry_credential"),
        (".pypirc", "package_index_token"),
        ("etc/ssl/private/server.key", "tls_private_key"),
        ("etc/pki/tls/private/x.key", "tls_private_key"),
        ("etc/letsencrypt/live/example.com/privkey.pem", "tls_private_key"),
        ("proc/self/environ", "process_environment"),
        ("id_ecdsa", "ssh_key"),
        ("id_dsa", "ssh_key"),
        ("id_xmss", "ssh_key"),
        ("etc/ssh/ssh_host_rsa_key", "ssh_key"),
    ])
    def test_each_added_family_is_refused_under_its_category(self, name, category):
        match = classify_text(name)
        assert match is not None, f"{name!r} was not classified"
        assert match.category == category


class TestTheRejectedCandidatesStayRejected:
    """Each of these was proposed, tested, and turned down with evidence.

    They are tested rather than only commented because a future author reaching
    for "block anything named like a secret" will reach for exactly these, and a
    comment does not fail the build. The most important row is the last: a
    `secrets?` pattern blocks the runtime's own source, which is the clearest
    demonstration available that name-shaped matching is not classification.
    """

    @pytest.mark.parametrize("name,why", [
        ("tests/fixtures/ca.pem", "PEM is a container format, not a secret class"),
        ("keys/public.pem", "PEM holds public material as often as private"),
        ("certs/server.crt", "certificates are public by construction"),
        ("certs/server.cer", "certificates are public by construction"),
        ("assets/deck.key", ".key is also the Keynote extension"),
        ("locales/en.key", ".key is also an i18n extension"),
        ("docs/CREDENTIALS.md", "unanchored `credentials` hits our own docs"),
        ("etc/passwd", "world-readable by design; the secret moved to shadow"),
        ("auro_runtime/secrets.py", "a `secrets?` pattern blocks our own source"),
        ("auro_runtime/secrets_backends/__init__.py",
         "a `secrets?` pattern blocks our own source"),
    ])
    def test_the_rejected_pattern_would_have_caused_this_false_positive(self, name, why):
        assert classify_text(name) is None, f"{name!r} refused, but: {why}"


class TestTheTrackedTreeIsNotRefusedByItsOwnGuard:

    def test_no_tracked_file_is_classified_sensitive(self, repo_root):
        """The population that actually matters, checked against the real tree.

        A credential family added on paper can be validated against imagined
        paths indefinitely. The repository's own tracked files are the one
        corpus that is certainly real, and refusing any of them is a defect the
        moment it lands rather than a hypothetical.
        """
        import subprocess

        listed = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root, capture_output=True, text=True, timeout=60,
        )
        if listed.returncode != 0:
            pytest.skip("not a git checkout")
        tracked = [line for line in listed.stdout.splitlines() if line.strip()]
        assert tracked, "git ls-files returned nothing; the check would be vacuous"

        refused = {f: classify_text(f) for f in tracked if classify_text(f)}
        assert refused == {}, (
            f"the guard refuses this repository's own tracked files: "
            f"{ {k: v.category for k, v in refused.items()} }"
        )


class TestNormalisationIsSharedAndHostIndependent:

    @pytest.mark.parametrize("raw,expected", [
        (".ENV", ".env"),
        ("OUTPUT/.Env", "output/.env"),
        (".GIT", ".git"),
        ("__PYCACHE__", "__pycache__"),
        (".Auro_Archive", ".auro_archive"),
    ])
    def test_case_is_folded_on_every_platform(self, raw, expected):
        """
        Lowercasing used to happen only under `os.name == "nt"`, while the copy
        of this normalisation in the file tool lowercased always -- so the two
        layers disagreed about case semantics on Linux while both looked
        correct read on their own.

        It is unconditional now. The regex inventory carries IGNORECASE and so
        does not depend on this, but the tool's directory blocklist is an exact
        set membership test against lowercase literals, and `.GIT` reaches it
        only because the canonicaliser folded the case first.
        """
        assert canonicalize_path(raw) == expected

    @pytest.mark.parametrize("raw", [".env ", ".env.", ".env  ", ".env. "])
    def test_trailing_dots_and_spaces_are_stripped(self, raw):
        assert canonicalize_path(raw) == ".env"

    @pytest.mark.parametrize("raw", [".environment", "envelope.txt", ".sshrc"])
    def test_the_strip_is_not_a_prefix_match(self, raw):
        """Control for the case above: normalisation must not widen matching."""
        assert classify_text(raw) is None


class TestUncontainedPathsFailClosed:

    def test_a_path_outside_the_base_is_refused_with_a_reason(self, tmp_path):
        """
        Every caller contains before classifying, so being handed an uncontained
        path is a caller bug. The fail-closed answer to a bug in a security
        control is to refuse, and to say why -- returning None here would report
        "not sensitive" for a path this module never actually examined.
        """
        base = tmp_path / "workspace"
        base.mkdir()
        outside = tmp_path / "elsewhere" / "notes.txt"

        match = classify_resolved(outside, base)

        assert match is not None, (
            "an uncontained path was reported as not sensitive, which is "
            "indistinguishable from a clean verdict on a path that was checked"
        )
        assert match.category == UNCONTAINED

    def test_a_contained_ordinary_file_is_still_permitted(self, tmp_path):
        """Control: fail-closed must not mean refuse-everything."""
        base = tmp_path / "workspace"
        (base / "output").mkdir(parents=True)
        inside = base / "output" / "notes.txt"
        inside.write_text("ordinary", encoding="utf-8")

        assert classify_resolved(inside, base.resolve()) is None

    def test_the_workspace_ancestry_is_not_judged(self, tmp_path):
        """
        Only the portion inside the workspace is the tool's subject. A workspace
        that happens to live under a directory matching a credential pattern
        would otherwise refuse every file it contains -- the classifier would be
        judging the operator's directory layout rather than the tool's target.
        """
        base = tmp_path / ".ssh-backup" / "workspace"
        (base / "output").mkdir(parents=True)
        inside = base / "output" / "notes.txt"
        inside.write_text("ordinary", encoding="utf-8")

        assert classify_resolved(inside, base.resolve()) is None


class TestTheGuardRefusalText:
    """`README.md` quotes the sensitive-path refusal, so its wording is a claim.

    The guard's other coverage asserts that a refusal happened and which pattern
    matched; nothing held the sentence a reader is shown. Rewording it would
    make the README false with the suite green.
    """

    def test_the_refusal_names_the_argument_and_the_documented_reason(
        self, make_guard_context
    ):
        from auro_runtime.guards import get_guard_registry

        guard = get_guard_registry()["check_sensitive_paths"]
        verdict = guard(make_guard_context("read_file", {"path": ".env"}))

        assert verdict is not None, "precondition: a sensitive path must refuse"
        assert verdict.allowed is False
        assert "Path argument 'path' matches sensitive pattern." == verdict.message

    def test_an_ordinary_path_produces_no_refusal_text(self, make_guard_context):
        """Negative control: the message above is not emitted unconditionally."""
        from auro_runtime.guards import get_guard_registry

        guard = get_guard_registry()["check_sensitive_paths"]

        assert guard(make_guard_context("read_file", {"path": "output/notes.txt"})) is None
