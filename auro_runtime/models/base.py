"""
Provider-neutral model backend protocol.

Any backend that can turn a system prompt + user message into an assistant
response string implements this Protocol. The kernel (orchestrator.py) depends
only on this shape, never on a specific provider SDK — see
auro_runtime.models.get_backend() for backend selection.
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class ModelBackend(Protocol):
    """A provider-neutral interface for single-turn text generation."""

    def resolve_model(self, model: str | None = None) -> str:
        """
        Return the model id `generate(model=...)` would actually call.

        Exists so a caller can find out *before* calling. A cost or policy
        gate needs the resolved id, not the requested one — a lesson paid
        for: the tool-level high-cost check cut on 2026-08-26 read the
        caller's argument, so omitting `model` skipped it entirely and the
        backend substituted its configured default just afterwards,
        selecting the expensive model right past the check meant to catch it.
        No shipped gate reads this today.
        """
        ...

    def generate(
        self,
        system_prompt: str,
        user_message: str,
        *,
        model: str | None = None,
        max_tokens: int = 4096,
    ) -> str:
        """
        Call the backend with a system prompt + user message.

        Returns the assistant's response text. Implementations resolve their
        own credentials (e.g. from environment variables) — there is no
        api_key parameter on this protocol.
        """
        ...
