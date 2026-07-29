"""
Tool catalog: list_tools returns registered tools with description and optional args summary.
"""

from auro_runtime.executor import get_registry, register
from auro_runtime.tool_schemas import ListToolsArgs


def _args_summary(schema) -> str:
    if schema is None:
        return "—"
    try:
        parts = []
        for name, f in schema.model_fields.items():
            ann = getattr(f, "annotation", None)
            if hasattr(ann, "__name__"):
                parts.append(f"{name} ({ann.__name__})")
            else:
                parts.append(name)
        return ", ".join(parts) if parts else "—"
    except Exception:
        return "—"


@register("list_tools", "List all registered tools with description and optional argument summary.", args_schema=ListToolsArgs)
def list_tools(include_args: bool = True) -> dict:
    """
    Return the list of registered tools for the orchestrator.
    include_args: if True, include a short argument summary per tool from its schema.
    """
    registry = get_registry()
    tools = []
    for name, (_, doc, schema) in sorted(registry.items()):
        entry = {"name": name, "description": (doc or "").strip() or "—"}
        if include_args:
            entry["args_summary"] = _args_summary(schema)
        tools.append(entry)
    return {"tools": tools, "count": len(tools)}
