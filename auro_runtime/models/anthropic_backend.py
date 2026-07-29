"""
Anthropic Claude backend, implementing the ModelBackend protocol. Resolves
credentials through the runtime's secret alias system when
AURO_ANTHROPIC_API_KEY_ALIAS is configured, with ANTHROPIC_API_KEY retained
as a compatibility fallback. Concatenates the text of the response content
blocks.

The `anthropic` SDK is an optional dependency (see pyproject.toml's
`anthropic` extra) and is imported lazily inside generate() so this module —
and the auro_runtime.models package that re-exports it — can be imported
without the SDK installed.
"""

import os

from auro_runtime.models.base import ModelBackend
from auro_runtime.secrets import get_secret

DEFAULT_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_MAX_TOKENS = 4096
API_KEY_ALIAS_ENV = "AURO_ANTHROPIC_API_KEY_ALIAS"


def _resolve_api_key() -> str:
    """
    Resolve the Anthropic API key without exposing it to the model.

    An explicitly configured alias fails closed: if it cannot be resolved, do
    not silently fall back to a raw environment key. ANTHROPIC_API_KEY remains
    available only when no alias has been selected.
    """
    alias = (os.environ.get(API_KEY_ALIAS_ENV) or "").strip()
    if alias:
        api_key = get_secret(alias)
        if api_key is None:
            raise RuntimeError(
                f"Anthropic API key alias '{alias}' is not configured or could not be resolved"
            )
        return api_key

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key and api_key.strip():
        return api_key.strip()
    raise RuntimeError(
        f"Set {API_KEY_ALIAS_ENV} to a configured secret alias, "
        "or set ANTHROPIC_API_KEY for compatibility"
    )


class AnthropicBackend(ModelBackend):
    """ModelBackend implementation calling the Anthropic Messages API."""

    def generate(
        self,
        system_prompt: str,
        user_message: str,
        *,
        model: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """
        Call Claude with system + user message. Returns the assistant message text.
        Uses Claude Haiku by default for low latency and cost.
        Resolves AURO_ANTHROPIC_API_KEY_ALIAS through the configured secret
        backend. Falls back to ANTHROPIC_API_KEY only when no alias is set.
        """
        from anthropic import Anthropic  # lazy: keep the SDK an optional extra

        client = Anthropic(api_key=_resolve_api_key())
        resolved_model = model or os.environ.get("AURO_MODEL", DEFAULT_MODEL)
        response = client.messages.create(
            model=resolved_model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        text = ""
        for block in response.content:
            if hasattr(block, "text"):
                text += block.text
        return text
