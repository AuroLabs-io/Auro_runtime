"""
Validate a directive file: parse front matter, check structure, verify referenced tools exist.
"""

from pathlib import Path

from auro_runtime.directive import load_directive, DIRECTIVE_ID_RE
from auro_runtime.executor import register, get_registry
from auro_runtime.paths import get_project_root
from auro_runtime.tool_schemas import ValidateDirectiveArgs

_REQUIRED_SECTIONS = ["Purpose", "Steps"]


@register(
    "validate_directive",
    "Validate a directive .md file: check YAML front matter, structure, and that referenced tools are registered.",
    args_schema=ValidateDirectiveArgs,
)
def validate_directive(path: str) -> dict:
    """
    Parse and validate a directive file. Returns errors/warnings without executing it.
    """
    base = get_project_root().resolve()
    p = (base / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    try:
        p.resolve().relative_to(base)
    except ValueError:
        return {"valid": False, "errors": ["Path is outside the allowed project directory."]}

    if not p.exists():
        return {"valid": False, "errors": [f"File not found: {path}"]}
    if not p.is_file() or not p.name.endswith(".md"):
        return {"valid": False, "errors": ["File must be a .md markdown file."]}

    errors = []
    warnings = []

    try:
        meta, body = load_directive(p)
    except Exception as e:
        return {"valid": False, "errors": [f"Failed to parse directive: {e}"]}

    if not meta.id or not DIRECTIVE_ID_RE.match(meta.id):
        errors.append(f"Invalid directive id: {meta.id!r} (must match ^[a-zA-Z0-9_.-]+$)")

    if not meta.description:
        warnings.append("Missing description in front matter (used for routing).")

    if not meta.tools:
        warnings.append("No tools listed in front matter — directive will have no tool access.")

    if meta.id != p.stem:
        errors.append(
            f"Directive id '{meta.id}' must match filename '{p.stem}.md'."
        )

    registry = get_registry()
    unknown_tools = [t for t in meta.tools if t not in registry]
    if unknown_tools:
        errors.append(f"Unknown tools (not registered): {', '.join(unknown_tools)}")

    if not body.strip():
        errors.append("Directive body is empty.")
    else:
        body_lower = body.lower()
        for section in _REQUIRED_SECTIONS:
            if f"## {section.lower()}" not in body_lower:
                warnings.append(f"Missing recommended section: ## {section}")

    if meta.category not in ("system", "task", "security", "debug"):
        warnings.append(f"Unknown category: {meta.category!r} (expected system/task/security/debug)")

    return {
        "valid": len(errors) == 0,
        "directive_id": meta.id,
        "description": meta.description,
        "tools": meta.tools,
        "category": meta.category,
        "errors": errors,
        "warnings": warnings,
    }
