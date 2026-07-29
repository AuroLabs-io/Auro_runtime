"""
Environment-variable secret backend and the default SecretBackend
implementation.

Secrets live in the process environment as AURO_SECRET_<ALIAS>. They are NOT
encrypted at rest — whatever set them (shell profile, .env file, systemd unit,
Docker, CI) is responsible for storage, and child processes inherit them by
default.

This backend works with deployment systems that inject environment variables
without making the kernel responsible for the system that stored them.
"""

import os

_ENV_PREFIX = "AURO_SECRET_"


class EnvSecretBackend:
    """Resolves aliases from AURO_SECRET_<ALIAS> environment variables."""

    name = "env"

    def get(self, alias: str) -> str | None:
        value = os.environ.get(_ENV_PREFIX + alias.upper())
        if value is not None and value.strip():
            return value.strip()
        return None

    def list_aliases(self) -> list[str]:
        return sorted(
            key[len(_ENV_PREFIX):].lower()
            for key in os.environ
            if key.startswith(_ENV_PREFIX)
        )
