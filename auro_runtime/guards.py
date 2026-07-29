"""
Policy guard registry and guard implementations.
Guards are pure functions that inspect a tool call and return a verdict.
The executor runs applicable guards between arg validation and tool invocation.
"""

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from auro_runtime.sanitization import (
    SECRET_PATTERNS,
    SENSITIVE_KEYS,
    sanitize_value,
    scrub_text,
    secret_kind,
)


@dataclass(frozen=True)
class GuardContext:
    """Immutable snapshot passed to every guard function."""

    tool_name: str
    raw_args: dict
    args: dict
    reason: str
    directive_id: str | None
    run_history: list[dict]


@dataclass(frozen=True)
class GuardVerdict:
    """Returned by a guard when it has an opinion about a tool call."""

    allowed: bool
    message: str
    code: str | None = None
    metadata: dict | None = None


GuardFn = Callable[[GuardContext], GuardVerdict | None]

_GUARD_REGISTRY: dict[str, GuardFn] = {}


def register_guard(name: str):
    """Decorator to register a guard function by name."""

    def decorator(fn: GuardFn) -> GuardFn:
        _GUARD_REGISTRY[name] = fn
        return fn

    return decorator


def get_guard_registry() -> dict[str, GuardFn]:
    return dict(_GUARD_REGISTRY)


# ---------------------------------------------------------------------------
# Audit redaction
# ---------------------------------------------------------------------------

_REDACT_KEYS = SENSITIVE_KEYS


def redact_for_audit(args: dict, matched_fields: list[str] | None = None) -> dict:
    """Return a copy of args with sensitive values replaced by '[REDACTED]'."""
    out = sanitize_value(args)
    if matched_fields:
        for field_path in matched_fields:
            parts = field_path.split(".")
            obj = out
            for part in parts[:-1]:
                if isinstance(obj, dict) and part in obj:
                    obj = obj[part]
                else:
                    break
            else:
                if isinstance(obj, dict) and parts[-1] in obj:
                    obj[parts[-1]] = "[REDACTED]"

    return out


def redact_args_for_audit(args):
    """
    Deep copy of args with any secret-shaped VALUE replaced by '[REDACTED]',
    regardless of its key or how deeply it is nested.

    redact_for_audit() only redacts known-sensitive key names and field paths a
    guard already matched. This is for audit paths that run before — or instead
    of — the secret guard, such as schema-validation failure, where a secret
    under an innocuous key like `body` would otherwise be logged verbatim.
    """
    return sanitize_value(args)


# ---------------------------------------------------------------------------
# Guard implementations
# ---------------------------------------------------------------------------

@register_guard("check_reason_not_empty")
def check_reason_not_empty(ctx: GuardContext) -> GuardVerdict | None:
    if not ctx.reason.strip():
        return GuardVerdict(
            allowed=False,
            message="Tool call must include a non-empty reason field for audit logging.",
            code="empty_reason",
        )
    return None


_SECRET_PATTERNS = SECRET_PATTERNS


def _secret_kind(text: str) -> str | None:
    """Return the first matching secret pattern name, or None."""
    return secret_kind(text)


def scrub_secrets_from_text(text: str) -> str:
    """
    Replace secret-shaped substrings in free text with '[REDACTED]', keeping the
    surrounding text intact.

    For error messages rather than argument values. A pydantic ValidationError
    embeds the offending input in its message, so `str(e)` carries the raw value
    even when the parsed data has been redacted. Blanking the whole string would
    destroy the diagnostic, so only the matched span is removed.
    """
    return scrub_text(text)


def _scan_for_secrets(text: str) -> list[dict]:
    """Scan text for secret patterns. Returns list of {kind, field} dicts — never the raw value."""
    hits = []
    for kind, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            hits.append({"kind": kind})
    return hits


def _scan_dict_for_secrets(d: dict, prefix: str = "") -> list[dict]:
    """Recursively scan dict keys and values for secrets, returning field paths.

    Keys are scanned as well as values because this runs against `raw_args`,
    which is the model's unvalidated output: a key is exactly as
    attacker-controlled as a value, so a secret placed as a key would
    otherwise pass the scan untouched.
    """
    hits = []
    for k, v in d.items():
        field_path = f"{prefix}.{k}" if prefix else k
        if isinstance(k, str):
            kind = _secret_kind(k)
            if kind:
                hits.append({"kind": kind, "field": f"{prefix}<key>" if prefix else "<key>"})
        if isinstance(v, str):
            for kind, pattern in _SECRET_PATTERNS:
                if pattern.search(v):
                    hits.append({"kind": kind, "field": field_path})
        elif isinstance(v, dict):
            hits.extend(_scan_dict_for_secrets(v, field_path))
        elif isinstance(v, list):
            hits.extend(_scan_list_for_secrets(v, field_path))
    return hits


def _scan_list_for_secrets(items: list, prefix: str) -> list[dict]:
    """Scan list items, recursing into nested dicts and lists.

    Without the recursion a secret one level inside a list of dicts — e.g.
    {"headers": [{"Authorization": "..."}]} — bypassed the scanner entirely.
    """
    hits = []
    for i, item in enumerate(items):
        field_path = f"{prefix}[{i}]"
        if isinstance(item, str):
            for kind, pattern in _SECRET_PATTERNS:
                if pattern.search(item):
                    hits.append({"kind": kind, "field": field_path})
        elif isinstance(item, dict):
            hits.extend(_scan_dict_for_secrets(item, field_path))
        elif isinstance(item, list):
            hits.extend(_scan_list_for_secrets(item, field_path))
    return hits


@register_guard("check_no_secrets_in_args")
def check_no_secrets_in_args(ctx: GuardContext) -> GuardVerdict | None:
    hits = _scan_dict_for_secrets(ctx.raw_args)
    reason_hits = _scan_for_secrets(ctx.reason)
    for h in reason_hits:
        h["field"] = "reason"
    all_hits = hits + reason_hits
    if all_hits:
        kinds = sorted(set(h["kind"] for h in all_hits))
        fields = sorted(set(h.get("field", "") for h in all_hits))
        return GuardVerdict(
            allowed=False,
            message=f"Tool call args or reason appears to contain secrets ({', '.join(kinds)}).",
            code="secret_detected",
            metadata={"matched_kinds": kinds, "matched_fields": fields},
        )
    return None


_SENSITIVE_PATH_PATTERNS = [
    re.compile(r"(^|[\\/])\.env(\..*)?$", re.IGNORECASE),
    re.compile(r"(^|[\\/])\.ssh[\\/]", re.IGNORECASE),
    re.compile(r"(^|[\\/])id_rsa", re.IGNORECASE),
    re.compile(r"(^|[\\/])id_ed25519", re.IGNORECASE),
    re.compile(r"(^|[\\/])\.credentials", re.IGNORECASE),
    re.compile(r"(^|[\\/])auro_secrets\.yaml$", re.IGNORECASE),
    re.compile(r"(^|[\\/])\.auro_secrets\.yaml$", re.IGNORECASE),
    re.compile(r"(^|[\\/])\.gnupg[\\/]", re.IGNORECASE),
    re.compile(r"(^|[\\/])\.aws[\\/]", re.IGNORECASE),
    re.compile(r"(^|[\\/])credentials\.json$", re.IGNORECASE),
    re.compile(r"(^|[\\/])\.htpasswd$", re.IGNORECASE),
]

_PATH_ARG_KEYS = frozenset({
    "path", "source_path", "dest_path",
    "restore_to", "url", "file_path", "directory",
})


def _canonicalize_path(p: str) -> str:
    """Normalize a path string for security comparison."""
    p = p.replace("\\", "/")
    p = re.sub(r"%2[eE]", ".", p)
    try:
        from pathlib import PurePosixPath
        p = str(PurePosixPath(p))
    except Exception:
        pass
    if os.name == "nt":
        p = p.lower()
    return p


@register_guard("check_sensitive_paths")
def check_sensitive_paths(ctx: GuardContext) -> GuardVerdict | None:
    for key in _PATH_ARG_KEYS:
        val = ctx.args.get(key) or ctx.raw_args.get(key)
        if not val or not isinstance(val, str):
            continue
        canonical = _canonicalize_path(val)
        for pattern in _SENSITIVE_PATH_PATTERNS:
            if pattern.search(canonical):
                return GuardVerdict(
                    allowed=False,
                    message=f"Path argument '{key}' matches sensitive pattern.",
                    code="sensitive_path",
                    metadata={"key": key, "pattern": pattern.pattern},
                )
    return None


_RAW_CREDENTIAL_KEYS = frozenset({
    "client_id", "client_secret", "tenant_id", "subscription_id",
    "api_key", "token", "password", "secret", "access_token",
    "refresh_token", "private_key",
    # Header names: a raw token most often arrives as headers["Authorization"],
    # which is nested rather than top-level.
    "authorization", "auth", "x-api-key", "x-auth-token", "api-key",
})


def _find_raw_credential(node, prefix: str = "") -> tuple[str, str] | None:
    """
    Find the first credential-shaped key holding a non-empty string value.

    Recurses, because the common case is nested — headers={"Authorization": "..."}
    rather than a top-level token argument. Returns (field_path, key) or None.
    """
    if isinstance(node, dict):
        for key, val in node.items():
            key_lower = str(key).lower()
            field_path = f"{prefix}.{key}" if prefix else str(key)
            if key_lower.endswith("_alias"):
                continue  # naming an alias is exactly what we want
            if key_lower in _RAW_CREDENTIAL_KEYS and isinstance(val, str) and val.strip():
                return field_path, str(key)
            found = _find_raw_credential(val, field_path)
            if found:
                return found
    elif isinstance(node, list):
        for i, item in enumerate(node):
            found = _find_raw_credential(item, f"{prefix}[{i}]")
            if found:
                return found
    return None


@register_guard("check_no_raw_credentials")
def check_no_raw_credentials(ctx: GuardContext) -> GuardVerdict | None:
    found = _find_raw_credential(ctx.raw_args)
    if found:
        field_path, key = found
        return GuardVerdict(
            allowed=False,
            message=(
                f"Credential-like argument '{field_path}' must use an alias, not a raw value. "
                f"Use the tool's *_alias parameter (e.g. auth_alias) so the secret is resolved "
                f"at call time and never enters the transcript."
            ),
            code="raw_credential",
            metadata={"key": key, "field": field_path},
        )
    return None


def _count_write_paths(run_history: list[dict], write_tools: set[str]) -> set[str]:
    """Count distinct file paths written to in run history."""
    paths = set()
    for step in run_history:
        tool = step.get("tool", "")
        if tool not in write_tools:
            continue
        args = step.get("args", {})
        path = args.get("path") or ""
        if path:
            paths.add(path)
    return paths


@register_guard("check_no_bulk_writes")
def check_no_bulk_writes(ctx: GuardContext) -> GuardVerdict | None:
    write_tools = {"write_file"}
    if ctx.tool_name not in write_tools:
        return None
    current_path = ctx.args.get("path") or ""
    prior_paths = _count_write_paths(ctx.run_history, write_tools)
    if current_path and current_path in prior_paths:
        return None
    if len(prior_paths) >= 1 and current_path and current_path not in prior_paths:
        return GuardVerdict(
            allowed=False,
            message=f"Bulk write detected: already wrote to {len(prior_paths)} path(s), now targeting '{current_path}'. Requires explicit confirmation per path.",
            code="bulk_write",
            metadata={"prior_paths": sorted(prior_paths), "current_path": current_path},
        )
    return None


_DESTRUCTIVE_TOOLS = frozenset({
    "delete_file", "restore_file",
})


@register_guard("check_destructive_action")
def check_destructive_action(ctx: GuardContext) -> GuardVerdict | None:
    if ctx.tool_name in _DESTRUCTIVE_TOOLS:
        return GuardVerdict(
            allowed=False,
            message=f"Destructive action '{ctx.tool_name}' flagged for audit. Confirm this was intended.",
            code="destructive_action",
            metadata={"tool": ctx.tool_name},
        )
    return None


_DEFAULT_WRITE_BUDGET = 10

_WRITE_BUDGET_TOOLS = frozenset({
    "write_file", "delete_file", "restore_file",
})


@register_guard("check_write_budget")
def check_write_budget(ctx: GuardContext) -> GuardVerdict | None:
    if ctx.tool_name not in _WRITE_BUDGET_TOOLS:
        return None
    count = sum(1 for step in ctx.run_history if step.get("tool", "") in _WRITE_BUDGET_TOOLS)
    if count >= _DEFAULT_WRITE_BUDGET:
        return GuardVerdict(
            allowed=False,
            message=f"Write budget exceeded: {count} write operations already performed in this run (limit: {_DEFAULT_WRITE_BUDGET}).",
            code="write_budget_exceeded",
            metadata={"count": count, "budget": _DEFAULT_WRITE_BUDGET},
        )
    return None
