"""
Archive integrity: an archived file is never destroyed by a later one.

delete_file and write_file both move the previous copy into .auro_archive/ and report
it recoverable. This suite holds those reports to their word. Distinct files never share
an archive entry, an entry that already exists is never overwritten, restore_file refuses
a name it cannot resolve to exactly one original, and the retention caps govern everything
that enters the archive rather than the delete path alone.

The regression behind it was real and reproduced. Archive names were
`{timestamp_to_the_second}_{basename}`, discarding the directory, so two same-named files
in different directories deleted within one second resolved to a single name and
shutil.move overwrote the first without complaint. Both calls returned
`recoverable: true`, the manifest recorded both, and only the second file still existed.

Timestamps are frozen rather than raced: "deleted in the same second" is made a property
of the test instead of of how fast the machine ran. Each collision test also asserts that
its own inputs would have collided under the old naming rule, so a green run cannot mean
the scenario simply failed to arise.
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from runtime_tools import file_tools
from runtime_tools.file_tools import delete_file, restore_file, write_file


# --- local fixtures (this file only) ----------------------------------------


@pytest.fixture
def archive_probe(repo_root: Path):
    """
    Create probe files under output/ and undo every trace of them afterwards.

        rel = archive_probe("output/sub/a.txt", "content")   # creates it
        rel = archive_probe("output/sub/b.txt")              # registers only

    Registering without creating is for destinations a restore will produce. Teardown
    removes the probe files, any directory the helper had to create, every archive entry
    that appeared during the test, and rewrites manifest.jsonl to its exact prior bytes.
    The shared `temp_output_file` fixture handles files and archive blobs but not
    directories or the manifest, and this suite creates all three.
    """
    archive_dir = repo_root / file_tools._ARCHIVE_DIR_NAME
    manifest = archive_dir / "manifest.jsonl"
    archive_existed = archive_dir.is_dir()
    before_names = {p.name for p in archive_dir.iterdir()} if archive_existed else set()
    manifest_before = manifest.read_bytes() if manifest.is_file() else None

    registered: list[Path] = []
    made_dirs: list[Path] = []

    def _probe(rel_path: str, content: str | None = None) -> str:
        target = repo_root / rel_path
        registered.append(target)
        if not target.parent.exists():
            made_dirs.append(target.parent)
        if content is not None:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return rel_path

    yield _probe

    for target in registered:
        if target.is_file():
            target.unlink()
    for directory in made_dirs:
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    if archive_dir.is_dir():
        for entry in archive_dir.iterdir():
            if entry.is_file() and entry.name not in before_names:
                entry.unlink()
        if manifest_before is not None:
            manifest.write_bytes(manifest_before)
        elif manifest.is_file():
            manifest.unlink()
        if not archive_existed and not any(archive_dir.iterdir()):
            archive_dir.rmdir()


@pytest.fixture
def frozen_archive_clock(monkeypatch):
    """
    Pin the archive timestamp and return it.

    The defect needed two archive writes inside one clock second. Left to the wall
    clock, a slow run would separate them and the test would pass for the wrong reason.
    """
    fixed = datetime(2026, 8, 6, 12, 0, 0, tzinfo=timezone.utc)

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed

    monkeypatch.setattr(file_tools, "datetime", _FrozenDatetime)
    return fixed.strftime("%Y%m%d_%H%M%S")


def _legacy_archive_name(ts: str, rel_path: str) -> str:
    """The superseded naming rule: timestamp plus basename, directory discarded."""
    return f"{ts}_{Path(rel_path).name}"


# --- collisions --------------------------------------------------------------


class TestArchiveNameCollisions:
    def test_same_basename_in_different_directories_both_stay_recoverable(
        self, repo_root, archive_probe, frozen_archive_clock, audit_events
    ):
        """Two same-named files deleted in one second each restore with their own content."""
        ts = frozen_archive_clock
        sub = archive_probe("output/__auro_dup_probe_sub__/__auro_dup_probe__.txt", "AAA-from-subdir")
        top = archive_probe("output/__auro_dup_probe__.txt", "BBB-from-top")

        # Negative control: under the old rule these two paths produce one name. Without
        # this, a green test could just mean the inputs never collided in the first place.
        assert _legacy_archive_name(ts, sub) == _legacy_archive_name(ts, top)

        first = delete_file(sub)
        second = delete_file(top)
        assert first["recoverable"] is True
        assert second["recoverable"] is True
        assert first["archive_path"] != second["archive_path"], (
            "Two distinct files were archived under one name. The first is gone and "
            "delete_file reported it recoverable while destroying it."
        )

        archive_dir = repo_root / file_tools._ARCHIVE_DIR_NAME
        assert (archive_dir / first["archive_path"]).read_text(encoding="utf-8") == "AAA-from-subdir"
        assert (archive_dir / second["archive_path"]).read_text(encoding="utf-8") == "BBB-from-top"

        assert restore_file(first["archive_path"])["restored"] is True
        assert restore_file(second["archive_path"])["restored"] is True
        assert (repo_root / sub).read_text(encoding="utf-8") == "AAA-from-subdir"
        assert (repo_root / top).read_text(encoding="utf-8") == "BBB-from-top"

    def test_redeleting_one_path_in_the_same_second_keeps_both_versions(
        self, repo_root, archive_probe, frozen_archive_clock, audit_events
    ):
        """A path deleted, recreated and deleted again within a second archives twice."""
        ts = frozen_archive_clock
        rel = archive_probe("output/__auro_reserved_probe__.txt", "version one")
        first = delete_file(rel)
        (repo_root / rel).write_text("version two", encoding="utf-8")
        second = delete_file(rel)

        # Negative control: both archive writes landed inside the same frozen second,
        # which is the only condition under which the old naming rule collided.
        assert first["archive_path"].startswith(ts)
        assert second["archive_path"].startswith(ts)

        assert first["archive_path"] != second["archive_path"], (
            "The second delete reused the first delete's archive name, overwriting the "
            "earlier version."
        )
        archive_dir = repo_root / file_tools._ARCHIVE_DIR_NAME
        assert (archive_dir / first["archive_path"]).read_text(encoding="utf-8") == "version one"
        assert (archive_dir / second["archive_path"]).read_text(encoding="utf-8") == "version two"

    def test_archive_name_records_the_directory_not_only_the_basename(
        self, repo_root, archive_probe, frozen_archive_clock, audit_events
    ):
        """The archive name carries the file's directory, which is what made names unique."""
        rel = archive_probe("output/__auro_named_probe_sub__/__auro_named_probe__.txt", "payload")
        result = delete_file(rel)
        assert "__auro_named_probe_sub__" in result["archive_path"], (
            "The archive name discards the directory component, so any two same-named "
            "files are one timestamp collision away from sharing an entry."
        )


# --- restore ambiguity -------------------------------------------------------


class TestRestoreAmbiguity:
    def test_restore_refuses_an_archive_name_mapping_to_two_originals(
        self, repo_root, archive_probe
    ):
        """One archive name naming two different files is refused, not silently chosen."""
        archive_dir = repo_root / file_tools._ARCHIVE_DIR_NAME
        archive_dir.mkdir(parents=True, exist_ok=True)
        name = "20260101_000000___auro_ambiguous_probe__.txt"
        (archive_dir / name).write_text("surviving content", encoding="utf-8")

        first_dest = archive_probe("output/__auro_amb_a__/__auro_ambiguous_probe__.txt")
        second_dest = archive_probe("output/__auro_amb_b__/__auro_ambiguous_probe__.txt")
        with open(archive_dir / "manifest.jsonl", "a", encoding="utf-8") as f:
            for original in (first_dest, second_dest):
                f.write(json.dumps({"original_path": original, "archive_path": name}) + "\n")

        result = restore_file(name)

        assert result["restored"] is False
        assert "ambiguous" in result["error"].lower()
        assert result["ambiguous_originals"] == sorted([first_dest, second_dest])
        # Refusing must name the ambiguity rather than resolve it: the pre-fix code took
        # the last matching row, restoring one file's bytes under the other's path.
        assert not (repo_root / first_dest).exists()
        assert not (repo_root / second_dest).exists()
        assert (archive_dir / name).is_file(), "a refused restore must not consume the entry"

    def test_repeated_rows_for_one_original_are_not_ambiguous(self, repo_root, archive_probe):
        """Many manifest rows naming the same original still resolve and restore."""
        archive_dir = repo_root / file_tools._ARCHIVE_DIR_NAME
        archive_dir.mkdir(parents=True, exist_ok=True)
        name = "20260101_000000___auro_repeat_probe__.txt"
        (archive_dir / name).write_text("restored payload", encoding="utf-8")

        dest = archive_probe("output/__auro_repeat_probe__.txt")
        with open(archive_dir / "manifest.jsonl", "a", encoding="utf-8") as f:
            for _ in range(15):
                f.write(json.dumps({"original_path": dest, "archive_path": name}) + "\n")

        result = restore_file(name)

        assert result["restored"] is True, (
            "Repeated deletes of one path share an archive name benignly; refusing them "
            "would make the ambiguity check reject the archive's own normal history."
        )
        assert (repo_root / dest).read_text(encoding="utf-8") == "restored payload"


# --- retention ---------------------------------------------------------------


class TestArchiveRetention:
    def test_overwriting_a_file_prunes_stale_archive_entries(
        self, repo_root, archive_probe, audit_events
    ):
        """The age cap governs the write path too, not only delete_file."""
        archive_dir = repo_root / file_tools._ARCHIVE_DIR_NAME
        archive_dir.mkdir(parents=True, exist_ok=True)
        stale = archive_dir / "20200101_000000_output____auro_stale_probe__.txt"
        stale.write_text("older than the retention window", encoding="utf-8")
        aged = time.time() - (file_tools._ARCHIVE_MAX_AGE_DAYS + 1) * 86400
        os.utime(stale, (aged, aged))

        rel = archive_probe("output/__auro_prune_probe__.txt", "version one")
        result = write_file(rel, "version two")

        assert result["written"] is True
        assert "previous_version_archived" in result
        assert not stale.exists(), (
            "write_file archived a previous version without pruning. The 30-day and "
            "100MB caps are documented as governing the archive, but only delete_file "
            "enforced them, so a write-heavy workload grew it without bound."
        )
