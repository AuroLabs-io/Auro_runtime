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

Public rather than restricted under D-043. Every case here is a fact about this
repository's own inventory and normalisation -- which families it holds, which
non-secrets it must not refuse -- and teaches nothing transferable about
defeating path validation in general. The traversal and evasion corpora stay in
the restricted pack.
"""

from pathlib import Path

import pytest

from auro_runtime.sensitive_paths import (
    UNCONTAINED,
    canonicalize_path,
    classify_resolved,
    classify_text,
    classify_workspace_relative,
)
from runtime_tools.file_tools import read_file


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
