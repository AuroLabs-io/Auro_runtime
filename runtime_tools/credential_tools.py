"""
Credential proxy: resolve secret aliases without ever returning or logging the value.
"""

from auro_runtime.executor import register
from auro_runtime.secrets import get_secret
from auro_runtime.tool_schemas import ResolveSecretArgs


@register("resolve_secret", "Check if a credential alias is configured; never returns the secret value.", args_schema=ResolveSecretArgs)
def resolve_secret(alias: str) -> dict:
    """
    Resolve a credential by alias. Returns only whether the alias is set; never returns the secret.
    Args: alias (str) — e.g. github_token, api_key.
    """
    if not alias or not isinstance(alias, str):
        return {"resolved": False, "error": "alias must be a non-empty string"}
    value = get_secret(alias.strip())
    if value is None or value == "":
        return {"resolved": False, "error": f"alias '{alias}' is not configured"}
    return {"resolved": True, "alias": alias}
