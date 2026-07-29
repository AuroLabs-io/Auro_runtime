"""One structured sanitizer for caller, model, logging, and audit boundaries.

The runtime cannot know whether an arbitrary value is sensitive.  This module
enforces the narrower deterministic contract already used by the secret guard:
known secret-shaped strings and values under sensitive keys never cross an
outbound representation in the clear.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import Any

REDACTED = "[REDACTED]"
REDACTED_KEY = "[REDACTED_KEY]"

SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "authorization",
        "auth",
        "private_key",
        "key",
        "credential",
        "credentials",
    }
)

SECRET_PATTERNS = (
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github_pat_fine", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("slack_token", re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("aws_key", re.compile(r"AKIA[A-Z0-9]{16}")),
    (
        "bearer_token",
        re.compile(r"Bearer\s+[A-Za-z0-9_\-.]{20,}", re.IGNORECASE),
    ),
    (
        "generic_secret",
        re.compile(
            r"(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+]{16,}",
            re.IGNORECASE,
        ),
    ),
)


def secret_kind(text: str) -> str | None:
    """Return the first matching secret-pattern name, without returning a value."""
    if not isinstance(text, str):
        return None
    for kind, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return kind
    return None


def scrub_text(text: str) -> str:
    """Remove secret-shaped substrings while preserving useful surrounding text."""
    if not isinstance(text, str):
        return text
    for _, pattern in SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def _is_nonempty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes, bytearray, Mapping, list, tuple, set, frozenset)):
        return len(value) > 0
    return True


def sanitize_with_report(value: Any) -> tuple[Any, list[str]]:
    """Return a JSON-safe value and safe paths at which redaction occurred."""
    redacted_fields: set[str] = set()
    active_ids: set[int] = set()

    def mark(path: str) -> None:
        redacted_fields.add(path or "$")

    def walk(node: Any, path: str) -> Any:
        if node is None or isinstance(node, (bool, int, float)):
            return node
        if isinstance(node, Enum):
            return walk(node.value, path)
        if isinstance(node, str):
            if secret_kind(node):
                mark(path)
                return REDACTED
            return node
        if isinstance(node, (bytes, bytearray)):
            return walk(bytes(node).decode("utf-8", errors="replace"), path)
        if isinstance(node, BaseException):
            rendered = scrub_text(str(node))
            if rendered != str(node):
                mark(path)
            return rendered
        if isinstance(node, Path):
            return walk(str(node), path)

        model_dump = getattr(node, "model_dump", None)
        if callable(model_dump):
            return walk(model_dump(), path)
        if dataclasses.is_dataclass(node) and not isinstance(node, type):
            return walk(dataclasses.asdict(node), path)

        node_id = id(node)
        if node_id in active_ids:
            return "[RECURSIVE]"

        if isinstance(node, Mapping):
            active_ids.add(node_id)
            try:
                out: dict[Any, Any] = {}
                for raw_key, raw_value in node.items():
                    if isinstance(raw_key, str):
                        key_is_secret = secret_kind(raw_key) is not None
                        safe_key = REDACTED_KEY if key_is_secret else raw_key
                        if key_is_secret:
                            mark(f"{path}.<key>" if path else "$.<key>")
                    elif raw_key is None or isinstance(raw_key, (bool, int, float)):
                        safe_key = raw_key
                    else:
                        safe_key = scrub_text(str(raw_key))

                    safe_component = (
                        REDACTED_KEY
                        if safe_key == REDACTED_KEY
                        else str(safe_key).replace(".", "_")
                    )
                    child_path = f"{path}.{safe_component}" if path else f"$.{safe_component}"
                    if (
                        isinstance(raw_key, str)
                        and raw_key.lower() in SENSITIVE_KEYS
                        and _is_nonempty(raw_value)
                    ):
                        out[safe_key] = REDACTED
                        mark(child_path)
                    else:
                        out[safe_key] = walk(raw_value, child_path)
                return out
            finally:
                active_ids.remove(node_id)

        if isinstance(node, (list, tuple, set, frozenset)):
            active_ids.add(node_id)
            try:
                items = [
                    walk(item, f"{path}[{index}]" if path else f"$[{index}]")
                    for index, item in enumerate(node)
                ]
                if isinstance(node, (set, frozenset)):
                    items.sort(key=repr)
                return items
            finally:
                active_ids.remove(node_id)

        rendered = scrub_text(str(node))
        if rendered != str(node):
            mark(path)
        return rendered

    safe = walk(value, "$")
    return safe, sorted(redacted_fields)


def sanitize_value(value: Any) -> Any:
    """Return only the JSON-safe sanitized value."""
    safe, _ = sanitize_with_report(value)
    return safe


def sanitize_fields_with_report(**fields: Any) -> dict[str, Any]:
    """Sanitize named fields and attach safe, field-qualified provenance paths."""
    safe_fields: dict[str, Any] = {}
    redacted_fields: set[str] = set()
    for name, value in fields.items():
        safe_value, paths = sanitize_with_report(value)
        safe_fields[name] = safe_value
        for path in paths:
            suffix = "" if path == "$" else path[1:]
            redacted_fields.add(f"$.{name}{suffix}")
    safe_fields["redacted_fields"] = sorted(redacted_fields)
    return safe_fields
