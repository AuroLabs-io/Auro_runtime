"""
Provider-neutral model backend protocol.

Any backend that can turn a system prompt + user message into an assistant
response string implements this Protocol. The kernel (orchestrator.py) and
tools (generate_text_tools.py) depend only on this shape, never on a specific
provider SDK — see auro_runtime.models.get_backend() for backend selection.
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class ModelBackend(Protocol):
    """A provider-neutral interface for single-turn text generation."""

    def resolve_model(self, model: str | None = None) -> str:
        """
        Return the model id `generate(model=...)` would actually call.

        Exists so a caller can find out *before* calling. Cost and policy gates
        need the resolved id, not the requested one: `generate_text`'s
        high-cost check read the caller's argument, so omitting `model`
        skipped the gate entirely and the backend then substituted its
        configured default afterwards — selecting the expensive model just
        after the check that existed to guard against it.
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
