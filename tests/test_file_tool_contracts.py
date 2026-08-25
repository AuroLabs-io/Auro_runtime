"""
Published contracts of the filesystem tools in runtime_tools/file_tools.py.

file_tools is the sandbox boundary for a runtime that executes model-chosen tool
calls. Every claim this suite holds it to is one a reader can check in `README.md`
or `docs/API.md`: where write_file and delete_file may act, what read_file and
list_dir refuse, the 1 MiB caps on both reads and writes and the order the read cap
is checked in, what restore_file requires of a destination, and the shape of a
refusal when a path does not exist or is the wrong type.

The suite exists because a documented limit with no test is a claim rather than a
control: a revert of the fix behind it would otherwise go green. Several tests here
carry a false-positive control alongside the refusal they assert, because a guard
that refuses everything satisfies a refusal test and breaks the tool.

Every test that writes, deletes or restores uses `audit_events` or `temp_output_file`
from tests/conftest.py, plus the local `archive_probe` and `fs_probe` fixtures, so a
run leaves the working tree exactly as it found it.

If one of these goes red, do not weaken the assertion and do not patch
runtime_tools/file_tools.py from here.
"""

import os
from pathlib import Path
from unittest import mock

import pytest

from runtime_tools import file_tools
from runtime_tools.file_tools import delete_file, list_dir, read_file, restore_file, write_file


# --- local fixtures (this file only) ----------------------------------------


@pytest.fixture(autouse=True)
def archive_probe():
    """Restore `.auro_archive/` to exactly the state each test found it in.

    Autouse deliberately, following tests/test_sensitive_resource_classification.py.
    Only some tests touch the archive, but which ones is not knowable in advance: a
    regression in any refusal turns a tool that was supposed to decline into one that
    archives a file under a timestamped name the test never learns, and the debris
    then breaks a later test's baseline rather than the failing one's.

    `.auro_archive/manifest.jsonl` is append-only and shared, so a test that writes a
    row must put the file back exactly as it found it -- including the case where it
    did not exist at all -- or it leaves a ledger row for an archive blob that is gone.
    """
    archive_dir = file_tools._get_archive_dir()
    manifest = archive_dir / "manifest.jsonl"
    before = manifest.read_text(encoding="utf-8") if manifest.exists() else None
    existing = {p.name for p in archive_dir.iterdir()} if archive_dir.is_dir() else set()

    yield

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


@pytest.fixture
def fs_probe(repo_root: Path):
    """
    Create a real file directly on disk (bypassing write_file/delete_file) at a
    repo-relative path. Used to plant probes inside directories the tools themselves
    refuse to write to (auro_runtime/, runtime_tools/, policies/, .git/), so refusal
    tests don't have to touch any real project file.

    Creates parent directories as needed and removes exactly what it created --
    the probe file, and any directory this fixture had to create to hold it (only if
    still empty at teardown) -- even if the test fails.
    """
    created_files: list[Path] = []
    created_dirs: list[Path] = []

    def _make(rel_path: str, content: str = "auro contract-test probe -- safe to delete\n") -> str:
        target = (repo_root / rel_path).resolve()
        assert target == repo_root or repo_root in target.parents, (
            f"fs_probe refuses to write outside the repo root: {rel_path!r}"
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
        if f.exists() or f.is_symlink():
            f.unlink()
    for d in sorted(created_dirs, key=lambda p: len(str(p)), reverse=True):
        if d.is_dir() and not any(d.iterdir()):
            d.rmdir()


class TestModuleConstantsMatchSpec:
    """Tripwires so a silent drift in the sandbox's own configuration is caught here
    rather than discovered as a surprise elsewhere."""

    def test_writable_dirs_matches_documented_spec(self):
        assert file_tools._WRITABLE_DIRS == {"output", "drafts"}

    def test_delete_allowlisted_dirs_matches_documented_spec(self):
        assert file_tools._DELETE_ALLOWLISTED_DIRS == {"output", "drafts"}

    def test_write_and_delete_allowlists_do_not_diverge(self):
        """
        A directory writable but not delete-allowlisted (or the reverse) is a
        one-way door: a run could create a file it cannot then clean up, or
        remove one it could never have made. The two sets are meant to be the
        same set, so drift between them is the defect worth catching.
        """
        assert file_tools._WRITABLE_DIRS == file_tools._DELETE_ALLOWLISTED_DIRS

    def test_directives_is_protected_and_not_delete_allowlisted(self):
        assert "directives" not in file_tools._WRITABLE_DIRS
        assert "directives" in file_tools._PROTECTED_PATTERNS
        assert "directives" not in file_tools._DELETE_ALLOWLISTED_DIRS

    def test_protected_patterns_matches_documented_spec(self):
        assert file_tools._PROTECTED_PATTERNS == {
            "auro_runtime", "runtime_tools", "policies", "directives", ".git", ".gitignore",
        }

    def test_read_blocklist_matches_documented_spec(self):
        assert file_tools._READ_BLOCKLIST_DIRS == {".auro_archive", ".git", "__pycache__"}
        assert file_tools._READ_BLOCKLIST_PREFIXES == ()
        assert file_tools._READ_BLOCKLIST_SUFFIXES == (".pyc",)

    def test_write_max_size_is_one_megabyte(self):
        assert file_tools._WRITE_MAX_SIZE_BYTES == 1024 * 1024


class TestPathTraversalContainment:
    """../ sequences and absolute paths outside the root are refused; paths that
    normalize back inside the root work correctly (no false positives)."""

    def test_read_file_rejects_dotdot_traversal_above_root(self):
        result = read_file("../__auro_traversal_probe__.txt")
        assert result["content"] is None
        assert "outside the allowed project directory" in result["error"]

    def test_list_dir_rejects_dotdot_traversal_above_root(self):
        result = list_dir("../")
        assert result["entries"] == []
        assert "outside the allowed project directory" in result["error"]

    def test_write_file_rejects_dotdot_traversal_above_root(self, repo_root):
        target = repo_root.parent / "__auro_traversal_probe__.txt"
        result = write_file("../__auro_traversal_probe__.txt", "should never land here")
        assert result["written"] is False
        assert "outside the allowed project directory" in result["error"]
        assert not target.exists()

    def test_delete_file_rejects_dotdot_traversal_above_root(self):
        result = delete_file("../__auro_traversal_probe__.txt")
        assert result["deleted"] is False
        assert "outside the allowed project directory" in result["error"]

    def test_read_file_rejects_deep_multi_segment_traversal(self):
        # A deep chain of "../" segments still resolves outside the root, and the
        # refusal must be the containment error rather than a missing-file error.
        result = read_file("output/../../../../../../tmp/__auro_deep_probe__.txt")
        assert result["content"] is None
        assert "outside the allowed project directory" in result["error"]

    def test_read_file_rejects_absolute_path_outside_root(self, tmp_path):
        outside = tmp_path / "secret.txt"
        outside.write_text("do not read me")
        result = read_file(str(outside))
        assert result["content"] is None
        assert "outside the allowed project directory" in result["error"]

    def test_list_dir_rejects_absolute_path_outside_root(self, tmp_path):
        result = list_dir(str(tmp_path))
        assert result["entries"] == []
        assert "outside the allowed project directory" in result["error"]

    def test_write_file_rejects_absolute_path_outside_root(self, tmp_path):
        target = tmp_path / "should_not_be_created.txt"
        result = write_file(str(target), "nope")
        assert result["written"] is False
        assert "outside the allowed project directory" in result["error"]
        assert not target.exists()

    def test_delete_file_rejects_absolute_path_outside_root(self, tmp_path):
        outside = tmp_path / "victim.txt"
        outside.write_text("do not delete me")
        result = delete_file(str(outside))
        assert result["deleted"] is False
        assert "outside the allowed project directory" in result["error"]
        assert outside.exists()

    def test_traversal_that_resolves_back_inside_root_reads_correctly(
        self, temp_output_file, audit_events
    ):
        rel = temp_output_file("output/__auro_traversal_inside_probe__.txt")
        write_file(rel, "still inside the sandbox")
        traversal_path = "output/../output/__auro_traversal_inside_probe__.txt"
        result = read_file(traversal_path)
        assert result.get("error") is None
        assert result["content"] == "still inside the sandbox"

    def test_traversal_through_writable_dir_into_source_tree_still_reads(self, repo_root):
        # Read access is intentionally broader than write access: reading real source
        # is fine even via a path that transits a writable dir first. This confirms
        # the containment check has no false positive here -- read is governed only by
        # the (narrow) read blocklist, not the (narrow) write allowlist.
        assert (repo_root / "auro_runtime" / "__init__.py").exists()
        result = read_file("output/../auro_runtime/__init__.py")
        assert result.get("error") is None
        assert result["content"] is not None

    def test_traversal_into_similarly_prefixed_sibling_directory_is_rejected(self):
        # A sibling directory whose name begins with the project root's own name is
        # still outside the root. The assertion is on the containment error
        # specifically, not on "does not exist" -- the latter would mean the
        # containment check had not decided and an existence check answered instead.
        result = read_file("../auro-runtime_sibling/__auro_probe__.txt")
        assert result["content"] is None
        assert "outside the allowed project directory" in result["error"]

    def test_write_file_traversal_that_lands_in_protected_dir_is_still_blocked(self, repo_root):
        traversal_path = "output/../auro_runtime/__auro_traversal_write_probe__.py"
        result = write_file(traversal_path, "should never land in protected source")
        assert result["written"] is False
        assert "protected directory" in result["error"]
        assert not (repo_root / "auro_runtime" / "__auro_traversal_write_probe__.py").exists()

    def test_windows_rooted_path_without_drive_letter_is_still_contained(self):
        # A rooted-no-drive path means two different things, so this asserts two.
        #
        # On Windows, Path(r"\foo").is_absolute() is False -- rooted, but carrying no
        # drive -- so file_tools takes the "relative" branch and joins it onto base,
        # and pathlib's own join semantics then re-root the segment at the LHS's
        # drive, landing outside base. The containment check has to catch that, and
        # the false negative it would otherwise be is the point of the test.
        #
        # On POSIX a backslash is an ordinary filename character, so the same string
        # is a single legal component: it joins inside base and stays there. There is
        # nothing to contain and the call fails on existence instead. Asserting that
        # the containment message is *absent* is what keeps this meaningful here --
        # it fails if POSIX ever starts re-rooting the segment.
        weird_path = r"\windows_rooted_no_drive_probe\evil.txt"
        assert Path(weird_path).is_absolute() is False  # documents the quirk being guarded against
        result = read_file(weird_path)
        assert result["content"] is None
        if os.name == "nt":
            assert "outside the allowed project directory" in result["error"]
        else:
            assert "does not exist" in result["error"]
            assert "outside the allowed project directory" not in result["error"]


class TestSymlinkHandling:
    """Item 4: a symlink placed inside an allowed directory must not be usable to
    read/write outside the project root. Path.resolve() follows symlinks and the
    containment checks run on the resolved path -- confirmed here, not just assumed."""

    def _symlink_or_skip(self, link_path: Path, target_path: Path) -> None:
        try:
            link_path.symlink_to(target_path)
        except (OSError, NotImplementedError) as e:
            pytest.skip(f"Symlink creation is not supported/permitted in this environment: {e}")

    def test_read_file_through_symlink_escaping_root_is_blocked(
        self, repo_root, tmp_path, temp_output_file
    ):
        outside_target = tmp_path / "outside_secret.txt"
        outside_target.write_text("top secret, must not be reachable via a symlink")
        link_rel = temp_output_file("output/__auro_symlink_read_probe__.txt")
        link_path = repo_root / link_rel
        self._symlink_or_skip(link_path, outside_target)
        try:
            result = read_file(link_rel)
            assert result["content"] is None
            assert "outside the allowed project directory" in result["error"]
        finally:
            if link_path.is_symlink() or link_path.exists():
                link_path.unlink()

    def test_write_file_through_symlink_escaping_root_is_blocked(
        self, repo_root, tmp_path, temp_output_file, audit_events
    ):
        outside_target = tmp_path / "outside_target.txt"
        outside_target.write_text("original content, must survive untouched")
        link_rel = temp_output_file("output/__auro_symlink_write_probe__.txt")
        link_path = repo_root / link_rel
        self._symlink_or_skip(link_path, outside_target)
        try:
            result = write_file(link_rel, "attempted overwrite via symlink")
            assert result["written"] is False
            assert "outside the allowed project directory" in result["error"]
            assert outside_target.read_text(encoding="utf-8") == "original content, must survive untouched"
        finally:
            if link_path.is_symlink() or link_path.exists():
                link_path.unlink()


class TestReadBlocklist:
    """Sensitive filenames and .pyc are refused; list_dir filters blocked entries
    instead of erroring."""

    def test_read_file_blocks_dotenv_at_root_even_when_nonexistent(self):
        # The block must fire before the existence check. .env does not exist in this
        # repo (it's gitignored) -- a "does not exist" error here would mean the block
        # is order-dependent on existence, which it must not be.
        result = read_file(".env")
        assert result["content"] is None
        assert "blocked" in result["error"].lower()
        assert "does not exist" not in result["error"].lower()

    def test_read_file_blocks_dotenv_case_insensitively(self):
        result = read_file(".ENV")
        assert result["content"] is None
        assert "blocked" in result["error"].lower()

    def test_read_file_blocks_auro_secrets_yaml_even_when_nonexistent(self):
        result = read_file("auro_secrets.yaml")
        assert result["content"] is None
        assert "blocked" in result["error"].lower()

    def test_read_file_blocks_dot_auro_secrets_yaml(self):
        result = read_file(".auro_secrets.yaml")
        assert result["content"] is None
        assert "blocked" in result["error"].lower()

    def test_read_file_blocks_dotenv_nested_in_a_writable_directory(self, fs_probe):
        probe_rel = fs_probe("output/.env", "API_KEY=should-not-be-readable")
        result = read_file(probe_rel)
        assert result["content"] is None
        assert "blocked" in result["error"].lower()

    def test_read_file_blocks_pyc_suffix(self, fs_probe):
        probe_rel = fs_probe("output/__auro_probe__.pyc", "not really bytecode")
        result = read_file(probe_rel)
        assert result["content"] is None
        assert "blocked" in result["error"].lower()

    def test_list_dir_filters_git_from_root_listing(self, fs_probe):
        # This repo checkout has no real .git directory (it is not itself
        # git-initialized), so plant one via fs_probe rather than depending on
        # incidental repo state -- this also makes the test deterministic regardless
        # of whether a given checkout happens to be a git repo.
        fs_probe(".git/__auro_probe__.txt")
        result = list_dir(".")
        names = {e["name"] for e in result["entries"]}
        assert ".git" not in names

    def test_list_dir_still_lists_non_blocked_dotfiles_and_known_entries(self):
        # .gitignore is protected from WRITE/DELETE by name -- a separate mechanism
        # from the read blocklist -- so it should still be visible here.
        result = list_dir(".")
        names = {e["name"] for e in result["entries"]}
        assert ".gitignore" in names
        assert "LICENSE" in names
        assert "auro_runtime" in names
        assert "runtime_tools" in names

    def test_list_dir_recursive_still_filters_pyc_suffix_in_nested_entries(self, fs_probe):
        fs_probe("output/__auro_cache_probe__/__pycache__/module.cpython-311.pyc", "x")
        result = list_dir("output/__auro_cache_probe__", recursive=True)
        names = {e["name"] for e in result["entries"]}
        assert not any(name.endswith(".pyc") for name in names)


class TestReadBlocklistAppliesToEveryPathComponent:
    """The blocklist matches *any* path component, not only the first one.

    `docs/API.md` states that read_file blocks "any path component under `.git`,
    `.auro_archive`, `__pycache__`". A blocked directory name is therefore refused
    wherever it sits, not only directly beneath the project root -- an agent that
    clones a repository into `output/` leaves `output/<repo>/.git/config`, and a
    remote URL in it can carry a credential.

    Do not weaken these assertions.
    """

    def test_nested_git_directory_is_hidden_from_list_dir(self, fs_probe):
        fs_probe("output/__auro_nested_repo__/.git/config", "[core]\nfake=true\n")
        result = list_dir("output/__auro_nested_repo__")
        names = {e["name"] for e in result["entries"]}
        assert ".git" not in names, (
            "Sandbox gap: a '.git' directory nested under an allowed write directory "
            "is listed by list_dir. _is_read_blocked only checks the top-level path "
            "component relative to the project root, not the immediate directory name."
        )

    def test_file_inside_nested_git_directory_is_unreadable(self, fs_probe):
        probe_rel = fs_probe(
            "output/__auro_nested_repo2__/.git/config",
            "[core]\nleaked-looking-value=should-not-be-readable\n",
        )
        result = read_file(probe_rel)
        assert result.get("content") is None, (
            "Sandbox gap: read_file served the contents of a file inside a '.git' "
            "directory that is nested under an allowed write directory rather than "
            "sitting directly at the project root."
        )

    def test_non_pyc_file_inside_nested_pycache_directory_is_unreadable(self, fs_probe):
        # Isolates the directory-name gap from the (working) .pyc suffix rule by using
        # a file that the suffix rule has no opinion about.
        probe_rel = fs_probe(
            "output/__auro_nested_cache__/__pycache__/notes.txt",
            "not bytecode -- should still be blocked by the directory name",
        )
        result = read_file(probe_rel)
        assert result.get("content") is None, (
            "Sandbox gap: a non-.pyc file inside a nested '__pycache__' directory is "
            "readable. Only the .pyc suffix rule happens to catch compiled files "
            "here; the directory-name blocklist does not apply below the project root."
        )



class TestWriteControl:
    def test_write_file_succeeds_in_output_dir(self, repo_root, temp_output_file, audit_events):
        rel = temp_output_file("output/__auro_write_ok_probe__.txt")
        content = "hello from the file-tools safety test suite"
        result = write_file(rel, content)
        assert result["written"] is True
        assert result["size"] == len(content)
        assert (repo_root / rel).read_text(encoding="utf-8") == content
        assert any(e["event"] == "file_written" for e in audit_events)

    @pytest.mark.parametrize(
        ("rel_path", "expected_substring"),
        [
            ("docs/__auro_write_refusal_probe__.txt", "designated directories"),
            ("__auro_write_refusal_probe__.txt", "designated directories"),
            ("auro_runtime/__auro_write_refusal_probe__.py", "protected directory"),
            ("runtime_tools/__auro_write_refusal_probe__.py", "protected directory"),
            ("policies/__auro_write_refusal_probe__.yaml", "protected directory"),
            (".git/__auro_write_refusal_probe__.txt", "protected directory"),
        ],
    )
    def test_write_file_refused_outside_writable_dirs(
        self, repo_root, temp_output_file, rel_path, expected_substring
    ):
        # Registered for cleanup even though the write must be refused. If the
        # guard ever stops refusing, the probe is written for real and would
        # otherwise be left in the tree -- breaking a later test's baseline
        # rather than this one's, which is the failure mode archive_probe
        # exists to prevent one layer down.
        temp_output_file(rel_path)
        result = write_file(rel_path, "should never be written")
        assert result["written"] is False
        assert expected_substring in result["error"]
        assert not (repo_root / rel_path).exists()

    def test_write_file_refused_at_the_project_root_itself(self):
        result = write_file(".", "should never be written")
        assert result["written"] is False
        assert "project root" in result["error"].lower()

    def test_write_file_overwrite_archives_previous_version(
        self, repo_root, temp_output_file, audit_events
    ):
        rel = temp_output_file("output/__auro_overwrite_probe__.txt")
        first = write_file(rel, "version one")
        assert first["written"] is True
        assert "previous_version_archived" not in first

        second = write_file(rel, "version two")
        assert second["written"] is True
        archive_name = second["previous_version_archived"]
        archive_path = repo_root / file_tools._ARCHIVE_DIR_NAME / archive_name
        assert archive_path.exists()
        assert archive_path.read_text(encoding="utf-8") == "version one"
        assert (repo_root / rel).read_text(encoding="utf-8") == "version two"

    def test_write_file_rejects_content_over_max_size(self, repo_root, temp_output_file):
        rel = temp_output_file("output/__auro_toolarge_probe__.txt")
        content = "a" * (file_tools._WRITE_MAX_SIZE_BYTES + 1)
        result = write_file(rel, content)
        assert result["written"] is False
        assert "exceeds max write size" in result["error"]
        assert not (repo_root / rel).exists()

    def test_read_file_rejects_a_file_over_max_size(self, repo_root, temp_output_file):
        """read_file refuses a file over the 1 MiB cap.

        Documented in `README.md` and in `docs/API.md`, which also states there is
        no range or chunked mode -- so an oversized file cannot be read at all,
        rather than being read in pieces.
        """
        rel = temp_output_file("output/__auro_bigread_probe__.txt")
        (repo_root / rel).write_text("a" * (file_tools._READ_MAX_SIZE_BYTES + 1), encoding="utf-8")

        result = read_file(rel)

        assert result["content"] is None, "the oversized file was read into the result"
        assert "read limit" in result["error"]

    def test_read_file_accepts_a_file_at_exact_max_size(self, repo_root, temp_output_file):
        """
        Boundary control. Without it, a cap that refused everything would pass
        the test above.
        """
        rel = temp_output_file("output/__auro_exactread_probe__.txt")
        (repo_root / rel).write_text("a" * file_tools._READ_MAX_SIZE_BYTES, encoding="utf-8")

        result = read_file(rel)

        assert result.get("error") is None, (
            f"a file at exactly the cap was refused: {result.get('error')}"
        )
        assert result["content"] is not None, "a file at exactly the cap must still be readable"
        assert len(result["content"]) == file_tools._READ_MAX_SIZE_BYTES

    def test_read_cap_is_checked_before_the_file_is_loaded(self, repo_root, temp_output_file):
        """
        The cap must come from stat(), not from len() of an already-read string.
        Measuring after reading means the allocation this limit exists to
        prevent has already happened by the time the tool objects.

        Proved by making the read itself fail: the file is removed between
        stat() and read_text(). A size check placed after the read would raise
        or return a read error; a check placed before it returns the size
        refusal, naming the limit.
        """
        rel = temp_output_file("output/__auro_readorder_probe__.txt")
        target = repo_root / rel
        target.write_text("a" * (file_tools._READ_MAX_SIZE_BYTES + 1), encoding="utf-8")

        real_read_text = Path.read_text

        def exploding_read_text(self, *a, **kw):
            raise AssertionError(
                "read_file loaded the file before checking its size — the cap is "
                "measured too late to prevent the allocation"
            )

        with mock.patch.object(Path, "read_text", exploding_read_text):
            result = read_file(rel)

        assert result["content"] is None
        assert "read limit" in result["error"]

    def test_write_file_accepts_content_at_exact_max_size(
        self, repo_root, temp_output_file, audit_events
    ):
        rel = temp_output_file("output/__auro_exactmax_probe__.txt")
        content = "a" * file_tools._WRITE_MAX_SIZE_BYTES
        result = write_file(rel, content)
        assert result["written"] is True
        assert result["size"] == file_tools._WRITE_MAX_SIZE_BYTES

    def test_write_file_size_limit_is_measured_in_encoded_bytes(
        self, repo_root, temp_output_file, audit_events
    ):
        """The 1 MiB write cap is measured in encoded bytes, not code points.

        `docs/API.md` states the cap as "1 MiB per write, measured in encoded
        bytes". A string of multi-byte characters is well under the cap by
        `len()` and several times over it once encoded, so the two readings are
        not interchangeable and the documented one is the one enforced.

        Do not weaken this assertion.
        """
        rel = temp_output_file("output/__auro_utf8_sizelimit_probe__.txt")
        max_bytes = file_tools._WRITE_MAX_SIZE_BYTES
        emoji = "\U0001F389"  # 1 Python character (code point), 4 bytes in UTF-8
        char_count = (max_bytes // 4) + 100
        content = emoji * char_count

        # Confirm the premise before asserting on tool behavior.
        assert len(content) < max_bytes, "premise broken: char count should be well under the cap"
        encoded_size = len(content.encode("utf-8"))
        assert encoded_size > max_bytes, "premise broken: encoded size should exceed the cap"

        result = write_file(rel, content)

        assert result["written"] is False, (
            f"write_file accepted {char_count} characters that encode to {encoded_size} "
            f"bytes, {encoded_size - max_bytes} bytes over the documented {max_bytes}-byte "
            "cap. The cap is specified in encoded bytes."
        )


class TestDeleteControl:
    def test_delete_file_soft_deletes_into_archive(self, repo_root, temp_output_file, audit_events):
        rel = temp_output_file("output/__auro_delete_probe__.txt")
        write_file(rel, "delete me softly")
        result = delete_file(rel)
        assert result["deleted"] is True
        assert result["archived"] is True
        assert not (repo_root / rel).exists()
        archive_path = repo_root / file_tools._ARCHIVE_DIR_NAME / result["archive_path"]
        assert archive_path.exists()
        assert archive_path.read_text(encoding="utf-8") == "delete me softly"
        assert any(e["event"] == "file_soft_deleted" for e in audit_events)

    @pytest.mark.parametrize("dir_name", ["auro_runtime", "runtime_tools", "policies", ".git"])
    def test_delete_file_refused_for_protected_directories(self, repo_root, fs_probe, dir_name):
        probe_rel = fs_probe(f"{dir_name}/__auro_delete_refusal_probe__.txt")
        result = delete_file(probe_rel)
        assert result["deleted"] is False
        assert dir_name in result["error"]
        assert (repo_root / probe_rel).exists()

    def test_delete_file_refused_for_protected_filename_even_inside_writable_dir(
        self, repo_root, fs_probe
    ):
        # '.gitignore' is protected by NAME, independent of which directory holds it.
        probe_rel = fs_probe("output/.gitignore", "test-probe\n")
        result = delete_file(probe_rel)
        assert result["deleted"] is False
        assert ".gitignore" in result["error"]
        assert (repo_root / probe_rel).exists()

    def test_delete_file_refused_for_directives_writable_but_not_delete_allowlisted(
        self, repo_root, fs_probe
    ):
        # directives/ is in _WRITABLE_DIRS but deliberately absent from
        # _DELETE_ALLOWLISTED_DIRS -- a good edge case for the two allowlists diverging.
        probe_rel = fs_probe("directives/__auro_delete_refusal_probe__.txt")
        result = delete_file(probe_rel)
        assert result["deleted"] is False
        assert "directives" in result["error"]
        assert (repo_root / probe_rel).exists()

    def test_delete_file_refused_for_directory_with_no_allowlist_membership_at_all(
        self, repo_root, fs_probe
    ):
        # docs/ is neither writable, delete-allowlisted, nor a protected pattern -- it
        # should be refused via the plain allowlist message, not the protected-dir one.
        probe_rel = fs_probe("docs/__auro_delete_refusal_probe__.txt")
        result = delete_file(probe_rel)
        assert result["deleted"] is False
        assert "designated directories" in result["error"]
        assert (repo_root / probe_rel).exists()

    def test_delete_file_on_nested_path_within_allowlisted_dir_succeeds(
        self, repo_root, temp_output_file, audit_events
    ):
        rel = temp_output_file("output/__auro_nested_delete_probe__/inner.txt")
        write_file(rel, "nested but still inside an allowed dir")
        try:
            result = delete_file(rel)
            assert result["deleted"] is True
            assert not (repo_root / rel).exists()
        finally:
            # delete_file only removes the leaf file; clean up the now-empty
            # directory it leaves behind so the tree stays exactly as it was.
            nested_dir = repo_root / "output" / "__auro_nested_delete_probe__"
            if nested_dir.is_dir() and not any(nested_dir.iterdir()):
                nested_dir.rmdir()


class TestRestoreFile:
    def test_restore_file_round_trips_using_manifest_lookup(
        self, repo_root, temp_output_file, audit_events
    ):
        rel = temp_output_file("output/__auro_restore_roundtrip__.txt")
        write_file(rel, "restore me")
        deleted = delete_file(rel)
        assert deleted["deleted"] is True
        assert not (repo_root / rel).exists()

        restored = restore_file(archive_name=deleted["archive_path"])
        assert restored["restored"] is True
        assert (repo_root / rel).exists()
        assert (repo_root / rel).read_text(encoding="utf-8") == "restore me"
        # moved back, not copied -- the archive entry should be gone
        assert not (repo_root / file_tools._ARCHIVE_DIR_NAME / deleted["archive_path"]).exists()

    def test_restore_file_with_explicit_restore_to(self, repo_root, temp_output_file, audit_events):
        original = temp_output_file("output/__auro_restore_explicit_src__.txt")
        write_file(original, "move me on restore")
        deleted = delete_file(original)
        new_rel = temp_output_file("output/__auro_restore_explicit_dst__.txt")

        restored = restore_file(archive_name=deleted["archive_path"], restore_to=new_rel)
        assert restored["restored"] is True
        assert (repo_root / new_rel).read_text(encoding="utf-8") == "move me on restore"
        assert not (repo_root / original).exists()

    def test_restore_file_nonexistent_archive_name_gives_clean_error(self):
        result = restore_file(archive_name="20200101_000000_never_existed.txt")
        assert result["restored"] is False
        assert "not found" in result["error"].lower()

    def test_restore_file_refuses_when_destination_already_exists(
        self, repo_root, temp_output_file, audit_events
    ):
        rel = temp_output_file("output/__auro_restore_conflict__.txt")
        write_file(rel, "original content")
        deleted = delete_file(rel)
        # Something else now occupies the original spot.
        write_file(rel, "someone already put something here")

        restored = restore_file(archive_name=deleted["archive_path"])
        assert restored["restored"] is False
        assert "already exists" in restored["error"]
        assert (repo_root / file_tools._ARCHIVE_DIR_NAME / deleted["archive_path"]).exists()

    def test_restore_file_restore_to_outside_project_root_is_rejected(
        self, repo_root, tmp_path, temp_output_file, audit_events
    ):
        rel = temp_output_file("output/__auro_restore_outside_src__.txt")
        write_file(rel, "should stay inside the sandbox")
        deleted = delete_file(rel)

        outside = tmp_path / "escaped.txt"
        restored = restore_file(archive_name=deleted["archive_path"], restore_to=str(outside))
        assert restored["restored"] is False
        assert "outside the allowed project directory" in restored["error"]
        assert not outside.exists()
        assert (repo_root / file_tools._ARCHIVE_DIR_NAME / deleted["archive_path"]).exists()


class TestRestoreDestinationIsAllowlisted:
    """A restore destination must pass the write allowlist, not just containment.

    `docs/API.md` states that restore_file's destination "must pass the write
    allowlist" -- the same one write_file enforces. Being under the project root
    is the weaker condition and is not sufficient on its own: `output/` and
    `drafts/` are the entire allowlist, so a destination inside `auro_runtime/`
    or `policies/` is contained and still refused.

    Reached through ordinary operations only -- write, then delete, then restore --
    so this is the shape an unremarkable run produces rather than a crafted one.

    Do not weaken this assertion.
    """

    def test_restore_to_must_be_in_a_writable_directory(
        self, repo_root, temp_output_file, audit_events
    ):
        probe_rel = temp_output_file("output/__auro_escape_c_probe__.txt")
        write_file(probe_rel, "restore-escape-C")
        deleted = delete_file(probe_rel)
        assert deleted["deleted"] is True

        escape_dest_rel = temp_output_file("auro_runtime/__auro_escape_c_probe__.py")

        result = restore_file(archive_name=deleted["archive_path"], restore_to=escape_dest_rel)

        assert result["restored"] is False, (
            "restore_file placed a file inside 'auro_runtime/' via restore_to. "
            "docs/API.md: the destination must pass the write allowlist, which is "
            "the same allowlist write_file enforces -- being under the project root "
            "is not sufficient."
        )
        assert not (repo_root / escape_dest_rel).exists()


class TestNonexistentPathsAndCleanErrors:
    """Nonexistent paths and file/directory type mismatches produce clean dict
    errors, not tracebacks."""

    def test_read_file_on_missing_file(self):
        result = read_file("output/__auro_does_not_exist__.txt")
        assert result["content"] is None
        assert "does not exist" in result["error"]

    def test_list_dir_on_missing_directory(self):
        result = list_dir("output/__auro_missing_dir__")
        assert result["entries"] == []
        assert "does not exist" in result["error"]

    def test_delete_file_on_missing_file(self):
        result = delete_file("output/__auro_does_not_exist__.txt")
        assert result["deleted"] is False
        assert "does not exist" in result["error"]

    def test_restore_file_on_missing_archive_entry(self):
        result = restore_file(archive_name="__auro_never_archived__.txt")
        assert result["restored"] is False
        assert "not found" in result["error"].lower()

    def test_read_file_on_a_directory_path_gives_clean_error(self, repo_root):
        assert (repo_root / "output").is_dir()
        result = read_file("output")
        assert result["content"] is None
        assert "not a file" in result["error"].lower()

    def test_list_dir_on_a_file_path_gives_clean_error(self, repo_root):
        assert (repo_root / "LICENSE").is_file()
        result = list_dir("LICENSE")
        assert result["entries"] == []
        assert "not a directory" in result["error"].lower()

    def test_delete_file_on_a_directory_path_gives_clean_error(self, repo_root):
        assert (repo_root / "output").is_dir()
        result = delete_file("output")
        assert result["deleted"] is False
        assert "not a file" in result["error"].lower()


class TestListDirRecursive:
    def test_recursive_includes_nested_entries(self, fs_probe):
        fs_probe("output/__auro_recursive_probe__/inner/nested_file.txt", "x")
        result = list_dir("output/__auro_recursive_probe__", recursive=True)
        names = {e["name"] for e in result["entries"]}
        assert "inner" in names
        assert "inner/nested_file.txt" in names

    def test_non_recursive_excludes_nested_entries(self, fs_probe):
        fs_probe("output/__auro_nonrecursive_probe__/inner/nested_file.txt", "x")
        result = list_dir("output/__auro_nonrecursive_probe__", recursive=False)
        names = {e["name"] for e in result["entries"]}
        assert names == {"inner"}

    def test_recursive_mode_does_not_descend_past_one_extra_level(self, fs_probe):
        # Documents current behavior: "recursive" here means "one extra level," not a
        # full tree walk -- a grandchild is not listed even with recursive=True. This
        # is a functionality quirk, not a security issue; noted for whoever next
        # relies on the name of this flag.
        fs_probe("output/__auro_depth_probe__/level1/level2/deep_file.txt", "x")
        result = list_dir("output/__auro_depth_probe__", recursive=True)
        names = {e["name"] for e in result["entries"]}
        assert "level1" in names
        assert "level1/level2" in names
        assert not any("deep_file.txt" in n for n in names)

    def test_recursive_still_respects_blocking_for_direct_children(self, fs_probe):
        fs_probe("output/__auro_recursive_block_probe__/thing.pyc", "x")
        result = list_dir("output/__auro_recursive_block_probe__", recursive=True)
        names = {e["name"] for e in result["entries"]}
        assert "thing.pyc" not in names


class TestDocumentedRefusalText:
    """The refusal strings `README.md` prints for a reader to recognise.

    Asserting the substring `protected directory` elsewhere proves the branch is
    taken; it does not hold the sentence the document quotes. These pin the text
    itself, so rewording the message fails here rather than making the README
    quietly false.
    """

    def test_a_write_into_a_protected_directory_refuses_and_names_it(self, repo_root):
        result = write_file("directives/__auro_protected_write_probe__.md", "x")

        assert result["written"] is False
        assert "Path is in protected directory 'directives'. Cannot write." in result["error"]
        assert not (repo_root / "directives" / "__auro_protected_write_probe__.md").exists()

    def test_a_write_outside_the_writable_dirs_refuses_with_the_documented_text(
        self, repo_root
    ):
        """The other refusal the README quotes, for a directory that is merely
        not writable rather than protected.

        `docs/` is the probe because it is neither in `_PROTECTED_PATTERNS` nor
        in `_WRITABLE_DIRS`, which is the branch this message belongs to — aiming
        at a protected directory would take the sentence above instead and prove
        nothing about this one.
        """
        result = write_file("docs/__auro_unwritable_dir_probe__.txt", "x")

        assert result["written"] is False
        assert (
            "Writes only allowed in designated directories (drafts, output). "
            "File is in 'docs'." in result["error"]
        )
        assert not (repo_root / "docs" / "__auro_unwritable_dir_probe__.txt").exists()

    def test_a_delete_inside_a_protected_directory_refuses_and_names_it(self, repo_root):
        """The probe is created directly rather than aimed at a real policy file.

        `delete_file` checks existence before it checks protection, so reaching
        the documented message needs a file that is really there — and pointing
        the test at a shipped policy would mean a permissive regression deletes
        one instead of failing.
        """
        probe = repo_root / "policies" / "__auro_protected_delete_probe__.yaml"
        probe.write_text("# disposable probe\n", encoding="utf-8")
        try:
            result = delete_file("policies/__auro_protected_delete_probe__.yaml")

            assert result["deleted"] is False
            assert (
                "Path is in protected directory 'policies'. Cannot delete."
                in result["error"]
            )
            assert probe.exists(), "the probe was removed from a protected directory"
        finally:
            probe.unlink(missing_ok=True)

    def test_widening_the_writable_dirs_onto_a_protected_one_is_refused(self, monkeypatch):
        """`AURO_RUNTIME_WRITABLE_DIRS` cannot be used to open a protected path.

        The refusal is a RuntimeError raised while reading the variable, so the
        runtime declines to start rather than running with the boundary removed
        — which is what the README says happens.
        """
        monkeypatch.setenv("AURO_RUNTIME_WRITABLE_DIRS", "output,directives")

        with pytest.raises(RuntimeError) as caught:
            file_tools._dirs_from_env(
                "AURO_RUNTIME_WRITABLE_DIRS", frozenset({"output", "drafts"})
            )

        assert (
            "AURO_RUNTIME_WRITABLE_DIRS cannot include protected directories: directives"
            in str(caught.value)
        )

    def test_an_ordinary_widening_still_succeeds(self, monkeypatch):
        """Negative control. Without this the refusal above would pass just as
        well against a reader that rejected every value it was given."""
        monkeypatch.setenv("AURO_RUNTIME_WRITABLE_DIRS", "output,reports")

        assert file_tools._dirs_from_env(
            "AURO_RUNTIME_WRITABLE_DIRS", frozenset({"output", "drafts"})
        ) == frozenset({"output", "reports"})


class TestRestoreFileArchiveNameContainment:
    """`archive_name` is resolved and contained like every other path argument.

    It names an entry inside `.auro_archive/`, so the resolved path must stay
    under that directory. Both forms below resolve outside it and both are
    refused; the source file is never read and the destination is never created.
    """

    def test_archive_name_outside_the_archive_directory_is_refused(
        self, repo_root, tmp_path, temp_output_file, audit_events
    ):
        outside = tmp_path / "outside_absolute.txt"
        outside.write_text("containment-probe-A", encoding="utf-8")
        dest_rel = temp_output_file("output/__auro_contain_absolute__.txt")

        result = restore_file(archive_name=str(outside), restore_to=dest_rel)

        assert result["restored"] is False, (
            "restore_file accepted an archive_name resolving outside the archive "
            f"directory ({outside}). Source file was "
            f"{'moved' if not outside.exists() else 'left in place'}."
        )
        assert outside.exists(), "a file outside the repo should never have been touched"
        assert not (repo_root / dest_rel).exists()

    def test_archive_name_traversing_out_of_the_archive_directory_is_refused(
        self, repo_root, temp_output_file, audit_events
    ):
        # The escape target sits beside the repo rather than under tmp_path. On the
        # Windows runners the checkout and the temp directory are on different
        # drives, and os.path.relpath raises ValueError across drives -- which
        # crashed this test in its own setup, before restore_file was ever called.
        # Both paths here are on the repo's drive, so the traversal is expressible
        # on any host. Same idiom as the dotdot probes above, which also write
        # beside the root and assert the file was never touched.
        outside = repo_root.parent / "__auro_contain_relative_probe__.txt"
        archive_dir = repo_root / file_tools._ARCHIVE_DIR_NAME
        dest_rel = temp_output_file("output/__auro_contain_relative__.txt")
        outside.write_text("containment-probe-B", encoding="utf-8")
        try:
            relative_name = os.path.relpath(str(outside), str(archive_dir))

            result = restore_file(archive_name=relative_name, restore_to=dest_rel)

            assert result["restored"] is False, (
                f"restore_file followed a relative archive_name ({relative_name!r}) "
                "out of the archive directory."
            )
            assert outside.exists(), "a file outside the repo should never have been touched"
            assert not (repo_root / dest_rel).exists()
        finally:
            outside.unlink(missing_ok=True)
