"""
File operations: list_dir, read_file, write_file, delete_file. Registered with the executor.
Paths are restricted to the project root to prevent path traversal.
delete_file is a soft delete — files are moved to .auro_archive/ with metadata.
"""

import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from auro_runtime.audit import write_audit_event
from auro_runtime.executor import register
from auro_runtime.paths import (
    get_directives_dir,
    get_policies_dir,
    get_workspace_root,
)
from auro_runtime.sensitive_paths import canonicalize_path, classify_workspace_relative
from auro_runtime.tool_schemas import DeleteFileArgs, EchoArgs, ListDirArgs, ReadFileArgs, RestoreFileArgs, WriteFileArgs

_BASE_DIR = None

_ARCHIVE_DIR_NAME = ".auro_archive"
_ARCHIVE_MAX_AGE_DAYS = 30
_ARCHIVE_MAX_SIZE_MB = 100
# Cap on the flattened relative path inside an archive filename. The timestamp
# prefix and any disambiguating suffix are added on top of this.
_ARCHIVE_NAME_MAX_CHARS = 150

_PROTECTED_PATTERNS = frozenset({
    "auro_runtime",
    "runtime_tools",
    "policies",
    "directives",
    ".git",
    ".gitignore",
})


def _dirs_from_env(env_var: str, default: frozenset[str]) -> frozenset[str]:
    """Read a directory allowlist without permitting protected-path widening."""
    raw = os.environ.get(env_var)
    if not raw:
        return default
    configured = frozenset(d.strip().lower() for d in raw.split(",") if d.strip())
    protected = configured & _PROTECTED_PATTERNS
    if protected:
        raise RuntimeError(
            f"{env_var} cannot include protected directories: "
            f"{', '.join(sorted(protected))}"
        )
    return configured


# Only destinations with a defined purpose are allowlisted. `exports`, `temp`,
# and `generated` shipped here with nothing writing to them; a name whose only
# distinguishing property is one that was never built is surface, not structure.
# `temp` returns when it is a real per-run workspace — see the run-scoped temp
# thread — rather than as an unenforced label.
_WRITABLE_DIRS = _dirs_from_env("AURO_RUNTIME_WRITABLE_DIRS", frozenset({
    "output",
    "drafts",
}))

_DELETE_ALLOWLISTED_DIRS = _dirs_from_env("AURO_RUNTIME_DELETE_ALLOWLISTED_DIRS", frozenset({
    "output",
    "drafts",
}))

_WRITE_MAX_SIZE_BYTES = 1024 * 1024  # 1MB per write

# Deliberately the same figure as the write cap. read_file previously had no cap
# at all, so a single call could pull an arbitrarily large file into the tool
# result and from there into model context — a cost and context-exhaustion path
# reachable by any directive holding read_file, which is most of them.
#
# Refuses rather than truncating. A truncated read that reported success would
# hand the model a fragment it has no way to recognise as partial, and a
# confident summary of the first megabyte of a log is worse than an error.
_READ_MAX_SIZE_BYTES = _WRITE_MAX_SIZE_BYTES

_READ_BLOCKLIST_DIRS = frozenset({
    ".auro_archive",
    ".git",
    "__pycache__",
})

# The sensitive-file inventory that used to sit here (`.env`, `auro_secrets.yaml`,
# `.auro_secrets.yaml`) is gone. It was one of three hand-maintained copies that
# drifted from each other, each reporting agreement with itself, so a credential
# family added to the policy guard was still readable through this tool. The
# single definition now lives in auro_runtime.sensitive_paths and this module
# consumes it below. The lists that remain here are a different control family --
# hygiene, not confidentiality -- and stay local deliberately.

_READ_BLOCKLIST_PREFIXES = ()

_READ_BLOCKLIST_SUFFIXES = (
    ".pyc",
)


def _is_read_blocked(p: Path, base: Path) -> str | None:
    """Return error if this path should not be readable, or None if OK."""
    try:
        rel = p.resolve().relative_to(base)
    except ValueError:
        return "Path is outside the allowed project directory."

    parts = rel.parts
    if not parts:
        return None

    # Normalisation comes from the shared canonicaliser rather than a copy kept
    # here. This module used to carry its own, which is how the two enforcement
    # layers ended up disagreeing about case on Linux -- that copy lowercased
    # always, the guard's lowercased only under os.name == "nt". Two normalisers
    # that must agree and have no mechanism forcing them to are one normaliser
    # with a latent bug.
    #
    # Applied per component, on every platform. Windows discards trailing dots
    # and spaces when it opens a file, so `.env ` and `.env.` both reach the
    # real `.env` while comparing unequal to it as strings. Confirmed live
    # 2026-08-16: this function returned None for `.env `, and the read that
    # followed returned the real file's contents.
    name = canonicalize_path(p.name)

    # Check every path component, not just the top one: a nested .git/, __pycache__/
    # or .auro_archive/ anywhere below the root must be blocked too.
    for part in parts:
        if canonicalize_path(part) in _READ_BLOCKLIST_DIRS:
            return f"Access to '{part}' is blocked."

    # Confidentiality, from the one shared inventory. `rel` is derived from
    # p.resolve(), so the subject here is the file the filesystem will open --
    # not the string the caller sent, which the policy guard judged earlier and
    # which can differ whenever resolution does any work.
    if classify_workspace_relative(rel) is not None:
        return f"Access to '{p.name}' is blocked (sensitive file)."

    if any(name.startswith(pf) for pf in _READ_BLOCKLIST_PREFIXES):
        return f"Access to '{p.name}' is blocked (data file)."

    if any(name.endswith(sf) for sf in _READ_BLOCKLIST_SUFFIXES):
        return f"Access to '{p.name}' is blocked."

    return None


def _get_base_dir() -> Path:
    """Frozen writable workspace root."""
    global _BASE_DIR
    if _BASE_DIR is None:
        _BASE_DIR = get_workspace_root().resolve()
    return _BASE_DIR


def _path_under_base(path: Path, base: Path) -> bool:
    """True if path resolves to a location under base (no escape)."""
    try:
        path.resolve().relative_to(base)
        return True
    except ValueError:
        return False


def _resolve_read_path(path: str) -> tuple[Path, Path]:
    """
    Resolve reads against the writable workspace or an immutable authority mount.

    The relative prefixes directives/ and policies/ are reserved virtual mounts.
    Writes, deletes, restores, and archives never call this helper and therefore
    remain workspace-only.
    """
    workspace = _get_base_dir()
    raw = Path(path)
    authority_roots = (get_directives_dir().resolve(), get_policies_dir().resolve())

    if raw.is_absolute():
        resolved = raw.resolve()
        # Prefer the narrower authority root when editable-source mode places
        # package resources underneath the workspace.
        for authority_root in authority_roots:
            if _path_under_base(resolved, authority_root):
                return resolved, authority_root
        return resolved, workspace

    parts = raw.parts
    if parts:
        mount = parts[0].lower()
        if mount == "directives":
            base = authority_roots[0]
            return (base.joinpath(*parts[1:])).resolve(), base
        if mount == "policies":
            base = authority_roots[1]
            return (base.joinpath(*parts[1:])).resolve(), base
    return (workspace / raw).resolve(), workspace


@register("list_dir", "List directory contents; path and optional recursive.", args_schema=ListDirArgs)
def list_dir(path: str, recursive: bool = False) -> dict:
    """
    List files and directories at the given path.
    Blocked directories are filtered from results.
    """
    p, base = _resolve_read_path(path)
    if not _path_under_base(p, base):
        return {"error": "Path is outside the allowed project directory.", "entries": []}
    blocked = _is_read_blocked(p, base)
    if blocked:
        return {"error": blocked, "entries": []}
    if not p.exists():
        return {"error": f"Path does not exist: {path}", "entries": []}
    if not p.is_dir():
        return {"error": f"Not a directory: {path}", "entries": []}
    entries = []
    for child in sorted(p.iterdir()):
        if _is_read_blocked(child, base):
            continue
        name = child.name
        kind = "dir" if child.is_dir() else "file"
        entries.append({"name": name, "kind": kind})
        if recursive and child.is_dir():
            for sub in sorted(child.iterdir()):
                if _is_read_blocked(sub, base):
                    continue
                entries.append({"name": f"{name}/{sub.name}", "kind": "dir" if sub.is_dir() else "file"})
    return {"path": str(p), "entries": entries}


@register("read_file", "Read file contents; path and optional encoding.", args_schema=ReadFileArgs)
def read_file(path: str, encoding: str = "utf-8") -> dict:
    """
    Read the contents of a file.
    Sensitive files are access-controlled.
    """
    p, base = _resolve_read_path(path)
    if not _path_under_base(p, base):
        return {"error": "Path is outside the allowed project directory.", "content": None}
    blocked = _is_read_blocked(p, base)
    if blocked:
        return {"error": blocked, "content": None}
    if not p.exists():
        return {"error": f"File does not exist: {path}", "content": None}
    if not p.is_file():
        return {"error": f"Not a file: {path}", "content": None}
    # Checked from stat() rather than after reading: measuring the string we
    # already loaded would mean the allocation this cap exists to prevent has
    # happened by the time we object.
    try:
        size_bytes = p.stat().st_size
    except OSError as e:
        return {"error": str(e), "content": None}
    if size_bytes > _READ_MAX_SIZE_BYTES:
        return {
            "error": (
                f"File is {size_bytes // 1024}KB, over the "
                f"{_READ_MAX_SIZE_BYTES // 1024}KB read limit. This tool reads whole "
                f"files only; it has no range or chunked mode."
            ),
            "content": None,
        }
    try:
        content = p.read_text(encoding=encoding)
        return {"path": str(p), "content": content}
    except Exception as e:
        return {"error": str(e), "content": None}


def _is_writable_path(p: Path, base: Path) -> str | None:
    """Return error message if path is not in a writable directory, or None if OK."""
    try:
        rel = p.resolve().relative_to(base)
    except ValueError:
        return "Path is outside the allowed project directory."
    parts = rel.parts
    if not parts:
        return "Cannot write to the project root."
    top = parts[0].lower()
    if top in _PROTECTED_PATTERNS:
        return f"Path is in protected directory '{parts[0]}'. Cannot write."
    if top not in _WRITABLE_DIRS:
        allowed = ", ".join(sorted(_WRITABLE_DIRS))
        return f"Writes only allowed in designated directories ({allowed}). File is in '{parts[0]}'."
    return None


@register(
    "write_file",
    "Write content to a file. Only allowed in designated directories "
    "(output, drafts). "
    "Existing files are backed up to .auro_archive/ before overwrite. Max 1MB per write.",
    args_schema=WriteFileArgs,
)
def write_file(path: str, content: str, encoding: str = "utf-8") -> dict:
    """
    Write content to a file. Creates parent directories if needed.
    Protected paths are blocked. Existing files are archived before overwrite.
    """
    # Measure the encoded byte length, not the code-point count: multi-byte text
    # would otherwise sail past the documented cap.
    try:
        content_bytes = len(content.encode(encoding))
    except (LookupError, UnicodeEncodeError) as e:
        return {"error": f"Cannot encode content as '{encoding}': {e}", "written": False}
    if content_bytes > _WRITE_MAX_SIZE_BYTES:
        return {
            "error": f"Content exceeds max write size ({_WRITE_MAX_SIZE_BYTES // 1024}KB).",
            "written": False,
        }

    base = _get_base_dir()
    p = (base / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    if not _path_under_base(p, base):
        return {"error": "Path is outside the allowed project directory.", "written": False}

    write_err = _is_writable_path(p, base)
    if write_err:
        return {"error": write_err, "written": False}

    backed_up = None
    if p.exists() and p.is_file():
        try:
            backed_up = _archive_file(p, base).name
        except Exception as e:
            return {"error": f"Failed to back up existing file: {e}", "written": False}

    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding=encoding)
        write_audit_event("file_written", path=str(path), size=len(content), backed_up=backed_up)
        result = {"path": str(p), "written": True, "size": len(content)}
        if backed_up:
            # Overwrites feed the same archive deletes do, so they have to prune
            # it too. Pruning only from delete_file meant a write-heavy,
            # delete-free workload grew .auro_archive/ past both documented caps
            # indefinitely — the caps read as archive-wide but governed one path
            # into it.
            _prune_archive()
            result["previous_version_archived"] = backed_up
        return result
    except Exception as e:
        return {"error": str(e), "written": False}


def _get_archive_dir() -> Path:
    return _get_base_dir() / _ARCHIVE_DIR_NAME


def _is_in_allowlisted_dir(p: Path, base: Path) -> bool:
    """True if the file is inside one of the allowlisted directories."""
    try:
        rel = p.resolve().relative_to(base)
    except ValueError:
        return False
    parts = rel.parts
    if not parts:
        return False
    return parts[0].lower() in _DELETE_ALLOWLISTED_DIRS


def _is_protected(p: Path, base: Path) -> str | None:
    """Return an error message if the path is in a protected area."""
    try:
        rel = p.resolve().relative_to(base)
    except ValueError:
        return "Path is outside the allowed project directory."
    parts = rel.parts
    if not parts:
        return "Cannot delete the project root."
    top = parts[0].lower()
    if top in _PROTECTED_PATTERNS:
        return f"Path is in protected directory '{parts[0]}'. Cannot delete."
    name = p.name.lower()
    if name in _PROTECTED_PATTERNS:
        return f"'{p.name}' is a protected file. Cannot delete."
    return None


def _reserve_archive_name(archive_dir: Path, ts: str, rel: Path) -> Path:
    """Claim an unused archive filename, creating it. Returns the reserved path."""
    archive_dir.mkdir(parents=True, exist_ok=True)

    # Flatten the relative path into the name rather than recreating real
    # subdirectories: _prune_archive only walks top-level files, so a nested
    # archive would be written and then never pruned by either cap. Naming the
    # copy after the basename alone is what let two same-named files from
    # different directories collide onto one entry.
    flat = "__".join(rel.parts)
    if len(flat) > _ARCHIVE_NAME_MAX_CHARS:
        # Keep the tail: the basename identifies the file better than the
        # leading directories, and the manifest holds the authoritative path.
        flat = flat[-_ARCHIVE_NAME_MAX_CHARS:]

    stem, ext = os.path.splitext(f"{ts}_{flat}")
    candidate = f"{stem}{ext}"
    attempt = 1
    while True:
        archive_path = archive_dir / candidate
        try:
            # O_EXCL, not a prior exists() check: shutil.move overwrites an
            # existing destination silently on both platforms, and a
            # check-then-move leaves a window for a concurrent worker to take
            # the same name inside the same one-second timestamp. Reserving the
            # name means the move can only ever land on our own placeholder, so
            # no archived file can be destroyed by a later one.
            fd = os.open(archive_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            attempt += 1
            candidate = f"{stem}_{attempt}{ext}"
            continue
        os.close(fd)
        return archive_path


def _archive_file(p: Path, base: Path) -> Path:
    """Move file to .auro_archive/ under a collision-free name. Returns archive path."""
    archive_dir = _get_archive_dir()
    rel = p.resolve().relative_to(base)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archive_path = _reserve_archive_name(archive_dir, ts, rel)
    try:
        shutil.move(str(p), str(archive_path))
    except Exception:
        # Never leave the empty reservation behind: it would be a zero-byte
        # entry that prune counts and restore_file would happily "restore".
        archive_path.unlink(missing_ok=True)
        raise

    manifest_path = archive_dir / "manifest.jsonl"
    entry = {
        "original_path": str(rel),
        "archive_path": str(archive_path.name),
        "deleted_at": datetime.now(timezone.utc).isoformat(),
        "size_bytes": archive_path.stat().st_size,
    }
    with open(manifest_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return archive_path


def _prune_archive() -> dict:
    """Remove archived files older than max age or if total size exceeds cap."""
    archive_dir = _get_archive_dir()
    if not archive_dir.is_dir():
        return {"pruned": 0}

    cutoff = time.time() - (_ARCHIVE_MAX_AGE_DAYS * 86400)
    max_bytes = _ARCHIVE_MAX_SIZE_MB * 1024 * 1024
    pruned = 0
    expired: list[str] = []
    over_capacity: list[str] = []

    files = []
    for f in archive_dir.iterdir():
        if f.name == "manifest.jsonl" or f.is_dir():
            continue
        files.append((f, f.stat().st_mtime, f.stat().st_size))

    for f, mtime, size in files:
        if mtime < cutoff:
            f.unlink(missing_ok=True)
            expired.append(f.name)
            pruned += 1

    files = [(f, mt, sz) for f, mt, sz in files if f.exists()]
    files.sort(key=lambda x: x[1])
    total = sum(sz for _, _, sz in files)
    while total > max_bytes and files:
        oldest, _, sz = files.pop(0)
        oldest.unlink(missing_ok=True)
        over_capacity.append(oldest.name)
        total -= sz
        pruned += 1

    if pruned:
        # This unlink is the only irreversible destruction of user content in
        # the runtime, and it was the one operation that wrote no audit record.
        # The archive names encode the original path, so the event says which
        # files went, and the two lists say why: age, or the size cap. Silence
        # still means nothing was destroyed.
        write_audit_event(
            "archive_pruned",
            pruned=pruned,
            expired=expired,
            over_capacity=over_capacity,
            retention_days=_ARCHIVE_MAX_AGE_DAYS,
            max_size_mb=_ARCHIVE_MAX_SIZE_MB,
        )

    return {"pruned": pruned}


@register(
    "delete_file",
    "Soft-delete a file: moves it to .auro_archive/ for recovery. "
    "Only allowed in designated directories (output, drafts). "
    "Protected paths (auro_runtime, runtime_tools, policies, directives, .git) are blocked.",
    args_schema=DeleteFileArgs,
)
def delete_file(path: str) -> dict:
    """
    Soft-delete a file by moving it to .auro_archive/.
    Blocked for protected directories. Only allowed in allowlisted dirs.
    Archived files are auto-pruned after 30 days or when archive exceeds 100MB.
    """
    base = _get_base_dir()
    p = (base / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()

    if not _path_under_base(p, base):
        return {"error": "Path is outside the allowed project directory.", "deleted": False}
    if not p.exists():
        return {"error": f"File does not exist: {path}", "deleted": False}
    if not p.is_file():
        return {"error": f"Not a file: {path}", "deleted": False}

    protected = _is_protected(p, base)
    if protected:
        return {"error": protected, "deleted": False}

    if not _is_in_allowlisted_dir(p, base):
        try:
            rel = p.resolve().relative_to(base)
            top = rel.parts[0] if rel.parts else "(root)"
        except ValueError:
            top = "(unknown)"
        allowed = ", ".join(sorted(_DELETE_ALLOWLISTED_DIRS))
        return {
            "error": f"Deletion only allowed in designated directories ({allowed}). "
                     f"File is in '{top}'.",
            "deleted": False,
        }

    try:
        archive_path = _archive_file(p, base)
        # Named for what happens, not for the tool that did it. This moves the
        # file into .auro_archive/ and it stays recoverable until pruning takes
        # it; calling that "deleted" told an auditor the file was gone while it
        # was still on disk. The retention bound travels with the event, because
        # the log otherwise cannot say how long recovery was possible.
        write_audit_event(
            "file_soft_deleted",
            path=str(path),
            archive=str(archive_path.name),
            retention_days=_ARCHIVE_MAX_AGE_DAYS,
        )
        _prune_archive()
        return {
            "path": str(p),
            "deleted": True,
            "archived": True,
            "archive_path": str(archive_path.name),
            "recoverable": True,
            "retention_days": _ARCHIVE_MAX_AGE_DAYS,
        }
    except Exception as e:
        return {"error": str(e), "deleted": False}


@register(
    "restore_file",
    "Restore a soft-deleted file from .auro_archive/. "
    "Use the archive_name from delete_file's response or check the manifest.",
    args_schema=RestoreFileArgs,
)
def restore_file(archive_name: str, restore_to: str | None = None) -> dict:
    """
    Restore an archived file to its original location or a specified path.
    Looks up the original path from the manifest if restore_to is not provided.
    """
    base = _get_base_dir()
    archive_dir = _get_archive_dir()

    # archive_name is attacker-influenced (it comes from model output), so it must
    # not be able to name anything outside the archive directory. Path("a") / "C:/x"
    # yields "C:/x", and ".." traverses out — either would let restore_file move an
    # arbitrary file from anywhere on disk into the sandbox, destructively (shutil.move).
    archive_path = (archive_dir / archive_name).resolve()
    if not _path_under_base(archive_path, archive_dir):
        return {"error": "Invalid archive name.", "restored": False}
    if not archive_path.exists() or not archive_path.is_file():
        return {"error": f"Archive file not found: {archive_name}", "restored": False}

    if restore_to:
        dest = (base / restore_to).resolve() if not Path(restore_to).is_absolute() else Path(restore_to).resolve()
        if not _path_under_base(dest, base):
            return {"error": "Restore path is outside the allowed project directory.", "restored": False}
        # Containment alone is not enough: without this, restore_to could place a file
        # into auro_runtime/ or policies/, which write_file itself refuses.
        not_writable = _is_writable_path(dest, base)
        if not_writable:
            return {"error": not_writable, "restored": False}
    else:
        manifest_path = archive_dir / "manifest.jsonl"
        if not manifest_path.exists():
            return {"error": "No manifest found. Provide restore_to path explicitly.", "restored": False}
        original_paths: list[str] = []
        for line in manifest_path.read_text(encoding="utf-8").strip().splitlines():
            try:
                entry = json.loads(line)
                if entry.get("archive_path") == archive_name:
                    candidate = entry.get("original_path")
                    if candidate and candidate not in original_paths:
                        original_paths.append(candidate)
            except (json.JSONDecodeError, KeyError):
                continue
        if not original_paths:
            return {"error": f"No manifest entry for '{archive_name}'. Provide restore_to path.", "restored": False}
        # Names written before the collision fix are not unique, so one archive
        # name can map to several different originals. Taking the last match --
        # what this did — restores a file under another file's path without
        # saying so. Repeated deletes of the SAME path are still unambiguous and
        # still restore, which is why this compares distinct originals, not rows.
        if len(original_paths) > 1:
            return {
                "error": (
                    f"Ambiguous archive name '{archive_name}': the manifest maps it to "
                    f"{len(original_paths)} different original paths "
                    f"({', '.join(sorted(original_paths))}). "
                    f"Pass restore_to to choose one explicitly."
                ),
                "restored": False,
                "ambiguous_originals": sorted(original_paths),
            }
        original_path = original_paths[0]
        dest = (base / original_path).resolve()
        if not _path_under_base(dest, base):
            return {"error": "Original path is outside the allowed project directory.", "restored": False}
        # Defense in depth: every legitimate manifest entry already points at a
        # writable directory, so this only rejects a tampered manifest.
        not_writable = _is_writable_path(dest, base)
        if not_writable:
            return {"error": not_writable, "restored": False}

    if dest.exists():
        return {
            "error": f"Destination already exists: {dest}. Delete or rename it first.",
            "restored": False,
        }

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(archive_path), str(dest))
        # Audit the workspace-relative path. An absolute one discloses the
        # deployment's filesystem layout to anything consuming the log, and it
        # would not correlate with the relative paths file_written and
        # file_soft_deleted record for the same file. Both branches above already
        # guarantee dest is under base; the fallback is defence in depth, because
        # audit must not raise on its way to the log.
        try:
            audit_dest = dest.relative_to(base).as_posix()
        except ValueError:
            audit_dest = dest.name
        write_audit_event("file_restored", archive=archive_name, restored_to=audit_dest)
        return {"restored": True, "path": str(dest), "from_archive": archive_name}
    except Exception as e:
        return {"error": str(e), "restored": False}


@register("echo", "Echo back a message (for testing).", args_schema=EchoArgs)
def echo(message: str) -> dict:
    """Echo a message. Useful for testing the orchestrator."""
    return {"message": message}
