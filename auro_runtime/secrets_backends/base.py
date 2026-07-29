"""
Internal SecretBackend protocol.

The kernel deliberately does not store secrets itself. Its built-in sources
share this small protocol so resolution can remain independent of storage.
This is an implementation seam for D1, not a public plugin interface.
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class SecretBackend(Protocol):
    """Resolves credential aliases to values."""

    def get(self, alias: str) -> str | None:
        """
        Return the secret for `alias`, or None if this backend does not have it.

        Returning None means "not found here" and lets the caller fall through
        to the next backend. Raise only for genuine misconfiguration (a missing
        dependency, an unreachable store) — a silent None for a broken backend
        is indistinguishable from a missing alias, which makes it impossible to
        debug.
        """
        ...

    def list_aliases(self) -> list[str]:
        """
        Return the alias names this backend knows about, without values.

        Backends that cannot enumerate cheaply may return an empty list.
        """
        ...
