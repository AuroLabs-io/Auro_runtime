"""
Provider-neutral model backend selection.

get_backend() picks a ModelBackend implementation by env AURO_MODEL_BACKEND
("anthropic" | "openai" | "openai_compatible"; default "anthropic"). Backend
classes are imported lazily inside get_backend() so importing this package
never requires a provider SDK to be installed.

generate(...) is the module-level convenience shim callers use instead of
importing a specific backend directly.

This module also owns the per-run model-call counter (build plan F6): the
kernel (auro_runtime.pipeline.runner) resets it at the start of each run, and
tools such as runtime_tools.generate_text_tools import it from here — so the
dependency points tools -> kernel, and the kernel never imports from the
tools package.
"""

import os
from contextvars import ContextVar

from auro_runtime.models.base import ModelBackend

__all__ = [
    "ModelBackend",
    "get_backend",
    "generate",
    "reset_call_counts",
    "get_call_count",
    "increment_call_count",
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


# --- Per-run model-call counter (owned here per F6; tools import it, never the reverse) ---

_call_count: ContextVar[int] = ContextVar("auro_model_call_count", default=0)


def reset_call_counts() -> None:
    """Reset the per-run model-call counter. Called by the pipeline at the start of each run."""
    _call_count.set(0)


def get_call_count() -> int:
    """Return the number of model calls recorded so far in this run."""
    return _call_count.get()


def increment_call_count() -> int:
    """Record one model call in this run and return the new total."""
    count = _call_count.get() + 1
    _call_count.set(count)
    return count
