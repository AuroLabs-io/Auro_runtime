"""
List available directives as an executor tool (usable from within directive runs).
"""

from auro_runtime.directive import list_directives as get_all_directives
from auro_runtime.executor import register
from auro_runtime.paths import get_directives_dir
from auro_runtime.tool_schemas import ListDirectivesArgs


@register(
    "list_directives",
    "List all available directives with id, description, tools, and category. Optionally filter by category.",
    args_schema=ListDirectivesArgs,
)
def list_directives(category: str | None = None) -> dict:
    """
    Return all directives from the directives directory.
    Optionally filter by category (system, task, security, debug).
    """
    directives_dir = get_directives_dir()
    if not directives_dir.is_dir():
        return {"error": "Directives directory not found.", "directives": []}

    items = get_all_directives(directives_dir)
    out = []
    for meta in items:
        if category and meta.category != category:
            continue
        out.append({
            "id": meta.id,
            "description": meta.description,
            "tools": meta.tools,
            "category": meta.category,
        })
    return {"directives": out, "count": len(out)}
