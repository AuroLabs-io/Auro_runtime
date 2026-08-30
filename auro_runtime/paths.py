"""Resolve immutable authority assets separately from writable workspace state."""

import os
from functools import lru_cache
from pathlib import Path


_PACKAGE_DIR = Path(__file__).resolve().parent
_SOURCE_ROOT = _PACKAGE_DIR.parent
_WORKSPACE_ENV = "AURO_WORKSPACE_ROOT"
_SOURCE_ROOT_ENV = "AURO_SOURCE_ROOT"
_LEGACY_ROOT_ENV = "AURO_ROOT"


def _validated_authority_root(path: Path, *, source: str) -> Path:
    root = path.resolve()
    missing = [
        name for name in ("directives", "policies")
        if not (root / name).is_dir()
    ]
    if missing:
        raise RuntimeError(
            f"{source} points to an incomplete Auro authority root '{root}'. "
            f"Missing directories: {', '.join(missing)}."
        )
    return root


def _validated_workspace_root(path: Path, *, source: str) -> Path:
    root = path.resolve()
    if not root.is_dir():
        raise RuntimeError(
            f"{source} points to a missing or non-directory workspace '{root}'."
        )
    return root


def get_authority_root() -> Path:
    """Installed, reviewed directives/ and policies/; never environment-selected."""
    packaged = _PACKAGE_DIR / "resources"
    return _validated_authority_root(packaged, source="packaged authority resources")


def get_directives_dir() -> Path:
    return get_authority_root() / "directives"


def get_policies_dir() -> Path:
    return get_authority_root() / "policies"


@lru_cache(maxsize=1)
def get_workspace_root() -> Path:
    """Writable tool/audit workspace; never used to discover authority assets."""
    explicit = os.environ.get(_WORKSPACE_ENV)
    if explicit:
        return _validated_workspace_root(Path(explicit), source=_WORKSPACE_ENV)

    legacy = os.environ.get(_LEGACY_ROOT_ENV)
    if legacy:
        return _validated_workspace_root(Path(legacy), source=_LEGACY_ROOT_ENV)

    # In a source checkout keep existing developer behavior. In an installed
    # wheel the source markers are absent, so cwd becomes workspace only; it is
    # never imported or searched for policies/directives.
    if (_SOURCE_ROOT / "pyproject.toml").is_file() and (_SOURCE_ROOT / "tests").is_dir():
        return _SOURCE_ROOT
    return _validated_workspace_root(Path.cwd(), source="current working directory")


def _validated_source_root(path: Path, *, source: str) -> Path:
    root = path.resolve()
    required = (
        Path("pyproject.toml"),
        Path("auro_runtime") / "__init__.py",
        Path("runtime_tools") / "__init__.py",
        Path("tests"),
    )
    missing = [str(marker) for marker in required if not (root / marker).exists()]
    if missing:
        raise RuntimeError(
            f"{source} does not identify a complete Auro source checkout '{root}'. "
            f"Missing: {', '.join(missing)}."
        )
    return root


def get_source_checkout_root() -> Path:
    """A real source checkout for developer verification tools, never a workspace guess."""
    explicit = os.environ.get(_SOURCE_ROOT_ENV)
    if explicit:
        return _validated_source_root(Path(explicit), source=_SOURCE_ROOT_ENV)
    return _validated_source_root(_SOURCE_ROOT, source="installed auro_runtime")


# get_project_root() was removed 2026-08-29. It was a compatibility alias for
# get_workspace_root(), and the name is the problem D-039 exists to retire: a
# single "project root" that a caller can read as the workspace, the authority
# tree, or the source checkout depending on what they came for. Its last
# production caller was validate_directive, which used it to resolve
# `directives/x.md` against the workspace -- correct only while a top-level
# mirror of the authority tree happened to sit there. That call now goes
# through the shared read resolver, leaving the alias with no callers at all.
#
# Ask for the root you actually mean: get_workspace_root() for writable state,
# get_authority_root() (or the directives/policies helpers) for what executes,
# get_source_checkout_root() for developer tooling. See
# OT-project-root-resolution-succeeds-by-accident, whose remaining half is the
# private app's own get_project_root().
