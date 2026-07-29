"""
Load and parse Markdown Directives with optional YAML front matter.
"""

import re
from pathlib import Path

import yaml

from auro_runtime.schemas import DirectiveMetadata


FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

# Safe directive ID: alphanumeric, underscore, hyphen, dot only (no path traversal)
DIRECTIVE_ID_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")


def allowed_tools_for(meta: DirectiveMetadata) -> set[str]:
    """
    Resolve a directive's tool scope. Fails closed.

    An empty or undeclared `tools:` grants NO tools. It must never expand to the
    full registry: doing so made an omitted or misspelled front-matter key
    (`tool:` for `tools:`) a silent privilege escalation that passed validation,
    because the parser defaults a missing key to an empty list. Empty scope now
    means empty, so a directive that declares nothing can do nothing and fails
    loudly at its first tool call instead of quietly gaining every tool.

    Callers must route through this rather than reading `meta.tools` directly,
    so the rule lives in one place.
    """
    return set(meta.tools)


def load_directive(path: Path | str) -> tuple[DirectiveMetadata | None, str]:
    """
    Load a directive from a Markdown file.

    Parses optional YAML front matter for id, description, tools.
    Returns (metadata or None if no/invalid front matter, full body or body after front matter).
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    metadata: DirectiveMetadata | None = None
    body = text

    match = FRONT_MATTER_RE.match(text)
    if match:
        try:
            data = yaml.safe_load(match.group(1))
            if data:
                raw_cat = data.get("category", "task")
                if isinstance(raw_cat, str):
                    raw_cat = raw_cat.strip().lower()
                category = raw_cat if raw_cat in ("system", "task", "security", "debug") else "task"
                metadata = DirectiveMetadata(
                    id=data.get("id", path.stem),
                    description=data.get("description", ""),
                    tools=data.get("tools", []),
                    category=category,
                )
        except Exception:
            pass
        body = text[match.end() :].lstrip()

    if metadata is None:
        metadata = DirectiveMetadata(id=path.stem, description="", tools=[], category="task")

    return metadata, body


def load_directive_by_id(directives_dir: Path | str, directive_id: str) -> tuple[DirectiveMetadata, str]:
    """
    Load a directive by ID: finds {id}.md in directives_dir, then loads it.

    Raises FileNotFoundError if no matching file exists.
    Raises ValueError if directive_id contains invalid characters (path traversal).
    """
    if not directive_id or not DIRECTIVE_ID_RE.match(directive_id):
        raise ValueError(f"Invalid directive ID: {directive_id!r}")
    directives_dir = Path(directives_dir).resolve()
    path = (directives_dir / f"{directive_id}.md").resolve()
    try:
        path.relative_to(directives_dir)
    except ValueError:
        raise ValueError(f"Invalid directive ID: {directive_id!r}")
    if not path.exists():
        raise FileNotFoundError(f"Directive not found: {directive_id} (looked for {path})")
    meta, body = load_directive(path)
    assert meta is not None
    if meta.id != directive_id:
        raise ValueError(
            f"Directive id mismatch: file '{path.name}' declares id '{meta.id}'."
        )
    return meta, body


def list_directives(directives_dir: Path | str) -> list[DirectiveMetadata]:
    """List all directives in a directory (all .md files)."""
    directives_dir = Path(directives_dir)
    result = []
    for path in sorted(directives_dir.glob("*.md")):
        meta, _ = load_directive(path)
        if meta:
            result.append(meta)
    return result
