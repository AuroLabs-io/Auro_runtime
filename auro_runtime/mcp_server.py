"""
MCP server for Auro. Exposes run_directive, list_directives, and list_tools.

Security: max_steps is clamped to 50. In streamable-http mode, Bearer auth is
enforced at the transport level via AURO_MCP_API_KEY. stdio mode has no auth
(local-only transport).
"""

import asyncio
import os
import secrets
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from auro_runtime.audit import write_audit_event
from auro_runtime.directive import DIRECTIVE_ID_RE, list_directives as get_directives_list
from auro_runtime.orchestrator import run as orchestrator_run
from auro_runtime.paths import (
    get_directives_dir,
    get_policies_dir,
    get_workspace_root,
)
from auro_runtime.sanitization import (
    sanitize_fields_with_report,
    sanitize_value,
    scrub_text,
)

_DIRECTIVES_DIR = get_directives_dir()
_POLICIES_DIR = get_policies_dir()

_MAX_STEPS_LIMIT = 50
_MCP_API_KEY = os.environ.get("AURO_MCP_API_KEY", "")
_ALLOWED_DIRECTIVE_IDS_ENV = "AURO_MCP_ALLOWED_DIRECTIVE_IDS"
_WORKSPACE_ENV = "AURO_WORKSPACE_ROOT"


def _load_allowed_directive_ids() -> frozenset[str]:
    """Parse the server-wide exposure set. Missing or empty means expose none."""
    raw = os.environ.get(_ALLOWED_DIRECTIVE_IDS_ENV, "")
    ids = frozenset(part.strip() for part in raw.split(",") if part.strip())
    invalid = sorted(directive_id for directive_id in ids if not DIRECTIVE_ID_RE.fullmatch(directive_id))
    if invalid:
        raise RuntimeError(
            f"{_ALLOWED_DIRECTIVE_IDS_ENV} contains invalid directive ids: "
            f"{', '.join(sanitize_value(invalid))}"
        )
    return ids


_ALLOWED_DIRECTIVE_IDS = _load_allowed_directive_ids()

_stdio_server = FastMCP("Auro", json_response=True)


def require_explicit_workspace() -> Path:
    """Refuse MCP startup unless its writable workspace is explicit and frozen."""
    raw = os.environ.get(_WORKSPACE_ENV, "").strip()
    if not raw:
        raise RuntimeError(
            f"{_WORKSPACE_ENV} must name an existing workspace before starting MCP."
        )
    expected = Path(raw).resolve()
    actual = get_workspace_root()
    if actual != expected:
        raise RuntimeError(
            "The Auro workspace was already resolved to "
            f"'{scrub_text(str(actual))}', not the configured MCP workspace "
            f"'{scrub_text(str(expected))}'. "
            "Restart the process with AURO_WORKSPACE_ROOT set before import."
        )
    return actual


def _ensure_tools():
    try:
        import runtime_tools  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            f"runtime_tools package failed to import: {scrub_text(str(e))}"
        ) from e


@_stdio_server.tool()
async def run_directive(
    directive_id: str,
    request: str,
    max_steps: int = 20,
) -> dict:
    """
    Run the orchestrator for one directive with the given user request.
    Returns a dict matching RunResult: success, messages, final_summary,
    error, meta, and legacy_steps.
    """
    if directive_id not in _ALLOWED_DIRECTIVE_IDS:
        safe_directive_id = scrub_text(directive_id)
        error = f"Directive '{safe_directive_id}' is not exposed by this MCP server."
        write_audit_event(
            "directive_not_exposed",
            **sanitize_fields_with_report(
                directive_id=directive_id,
                allowed_directive_ids=sorted(_ALLOWED_DIRECTIVE_IDS),
                error=f"Directive '{directive_id}' is not exposed by this MCP server.",
            ),
        )
        return {
            "success": False,
            "messages": [],
            "final_summary": None,
            "error": error,
            "meta": {
                "event": "directive_not_exposed",
                "directive_id": safe_directive_id,
            },
            "legacy_steps": [],
        }

    max_steps = max(1, min(max_steps, _MAX_STEPS_LIMIT))
    try:
        result = await asyncio.to_thread(
            orchestrator_run,
            directive_id,
            request or "No request provided.",
            directives_dir=_DIRECTIVES_DIR,
            policies_dir=_POLICIES_DIR,
            max_steps=max_steps,
            allowed_directive_ids=set(_ALLOWED_DIRECTIVE_IDS),
        )
        return result
    except FileNotFoundError as e:
        return {"success": False, "messages": [], "final_summary": None, "error": scrub_text(str(e)), "meta": {}, "legacy_steps": []}
    except Exception as e:
        return {"success": False, "messages": [], "final_summary": None, "error": scrub_text(str(e)), "meta": {}, "legacy_steps": []}


@_stdio_server.tool()
def list_directives(category: str | None = None) -> list[dict]:
    """
    List all directives with id, description, tools, and category.
    Optionally filter by category: system, task, or security.
    """
    items = get_directives_list(_DIRECTIVES_DIR)
    out = []
    for meta in items:
        if meta.id not in _ALLOWED_DIRECTIVE_IDS:
            continue
        if category and getattr(meta, "category", None) != category:
            continue
        out.append(sanitize_value(meta.model_dump()))
    return out


@_stdio_server.tool()
def list_tools(include_args: bool = True) -> dict:
    """
    List all registered tools with name, description, and optional args summary.
    """
    _ensure_tools()
    from runtime_tools.catalog_tools import list_tools as catalog_list_tools
    return sanitize_value(catalog_list_tools(include_args=include_args))


# ---------------------------------------------------------------------------
# Transport-level Bearer auth for streamable-http
# ---------------------------------------------------------------------------

class _ApiKeyTokenVerifier:
    """TokenVerifier that checks Bearer tokens against AURO_MCP_API_KEY."""

    async def verify_token(self, token: str):
        from mcp.server.auth.provider import AccessToken

        if not _MCP_API_KEY:
            return None
        if not secrets.compare_digest(token, _MCP_API_KEY):
            return None
        return AccessToken(
            token=token,
            client_id="auro_mcp_client",
            scopes=["all"],
        )


def create_stdio_server() -> FastMCP:
    """Return the stdio server only after validating its explicit workspace."""
    require_explicit_workspace()
    return _stdio_server


def create_authenticated_server(public_url: str) -> FastMCP:
    """Create an authenticated HTTP server bound to its advertised public URL."""
    from mcp.server.auth.settings import AuthSettings

    require_explicit_workspace()
    public_url = public_url.rstrip("/")
    auth_settings = AuthSettings(
        issuer_url=public_url,
        resource_server_url=public_url,
    )

    server = FastMCP(
        "Auro",
        json_response=True,
        auth=auth_settings,
        token_verifier=_ApiKeyTokenVerifier(),
    )

    server.tool()(run_directive)
    server.tool()(list_directives)
    server.tool()(list_tools)

    return server
