"""
Provider-neutral model backend selection.

get_backend() picks a ModelBackend implementation by env AURO_MODEL_BACKEND
("anthropic" | "openai" | "openai_compatible"; default "anthropic"). Backend
classes are imported lazily inside get_backend() so importing this package
never requires a provider SDK to be installed.

generate(...) is the module-level convenience shim callers use instead of
importing a specific backend directly.

This module owned the per-run model-call counter (build plan F6) until
2026-08-26. The counter was removed with generate_text, its only caller: with
nothing left to increment it, an exported accessor would have read zero for
the life of every run while the README claimed a cap. Model calls are now
bounded by the orchestrator's step cap instead.
"""

import os
from auro_runtime.models.base import ModelBackend

__all__ = [
    "ModelBackend",
    "get_backend",
    "generate",
    "resolve_model",
]

DEFAULT_BACKEND = "anthropic"


def get_backend() -> ModelBackend:
    """
    Construct the configured ModelBackend.

    Selection is by env AURO_MODEL_BACKEND: "anthropic" (default), "openai",
    or "openai_compatible" ("openai" and "openai_compatible" are aliases for
    the same OpenAI-compatible /v1/chat/completions backend).
    """
    backend_name = os.environ.get("AURO_MODEL_BACKEND", DEFAULT_BACKEND).strip().lower()

    if backend_name == "anthropic":
        from auro_runtime.models.anthropic_backend import AnthropicBackend
        return AnthropicBackend()
    if backend_name in ("openai", "openai_compatible"):
        from auro_runtime.models.openai_compatible_backend import OpenAICompatibleBackend
        return OpenAICompatibleBackend()

    raise ValueError(
        f"Unknown AURO_MODEL_BACKEND '{backend_name}'. Expected 'anthropic', 'openai', or 'openai_compatible'."
    )


def generate(
    system_prompt: str,
    user_message: str,
    *,
    model: str | None = None,
    max_tokens: int = 4096,
) -> str:
    """Generate via the configured backend. Convenience shim over get_backend()."""
    return get_backend().generate(system_prompt, user_message, model=model, max_tokens=max_tokens)


def resolve_model(model: str | None = None) -> str:
    """
    The model id a `generate(model=...)` call would actually use.

    Answers "what will this cost?" before committing to the call. No shipped
    gate consults it today — the one that did was cut with its tool on
    2026-08-26. It is kept because the question it answers is real and the
    lesson it encodes is worth not relearning: a check that reads the
    *requested* id sees nothing when `model=None`, which is the normal way to
    ask for the configured default, and the backend then substitutes that
    default immediately afterwards.
    """
    return get_backend().resolve_model(model)

