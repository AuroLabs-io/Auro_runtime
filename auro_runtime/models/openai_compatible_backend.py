"""
OpenAI-compatible chat-completions backend. Targets any endpoint speaking the
OpenAI /v1/chat/completions request/response shape: Ollama, vLLM, LM Studio,
llama.cpp, or a hosted provider (OpenAI, Groq, OpenRouter, ...).

Uses a plain `requests` POST rather than the `openai` SDK — `requests` is
already a core dependency, so this backend has no extra install requirement
and works out of the box against a local Ollama server.
"""

import os

import requests

from auro_runtime.models.base import ModelBackend

DEFAULT_BASE_URL = "http://localhost:11434/v1"  # Ollama's OpenAI-compatible endpoint
DEFAULT_MODEL = "llama3.1"
DEFAULT_MAX_TOKENS = 4096
DEFAULT_TIMEOUT_SECONDS = 120


class OpenAICompatibleBackend(ModelBackend):
    """ModelBackend implementation calling an OpenAI-compatible /v1/chat/completions endpoint."""

    def resolve_model(self, model: str | None = None) -> str:
        """The model id generate() will call. Single source of truth for it."""
        return model or os.environ.get("AURO_OPENAI_MODEL", DEFAULT_MODEL)

    def generate(
        self,
        system_prompt: str,
        user_message: str,
        *,
        model: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """
        Call an OpenAI-compatible chat-completions endpoint with system + user
        messages. Returns the assistant message text.

        base_url defaults to a local Ollama server (env AURO_OPENAI_BASE_URL);
        the API key is optional (env AURO_OPENAI_API_KEY) since most local
        servers don't require one; model defaults to env AURO_OPENAI_MODEL.
        """
        base_url = os.environ.get("AURO_OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
        api_key = os.environ.get("AURO_OPENAI_API_KEY")
        resolved_model = self.resolve_model(model)

        headers = {"Content-Type": "application/json"}
        if api_key and api_key.strip():
            headers["Authorization"] = f"Bearer {api_key.strip()}"

        payload = {
            "model": resolved_model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }

        url = f"{base_url}/chat/completions"
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT_SECONDS)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"OpenAI-compatible backend request to {url} failed: {e}") from e

        try:
            data = response.json()
        except ValueError as e:
            raise RuntimeError(f"OpenAI-compatible backend at {url} returned a non-JSON response: {e}") from e

        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise RuntimeError(
                f"OpenAI-compatible backend at {url} returned an unexpected response shape: {data}"
            ) from e
