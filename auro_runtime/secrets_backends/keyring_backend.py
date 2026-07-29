"""
Secret backend using Python's keyring package.

On a configured desktop, keyring may delegate to macOS Keychain, Windows
Credential Manager, or Linux Secret Service. Storage and unlock behavior
depend on the backend selected by the package, so the runtime does not make
blanket encryption guarantees.

Requires the optional `keyring` package: pip install auro-runtime[keyring]
"""

_SERVICE_NAME = "auro-runtime"


class KeyringSecretBackend:
    """Resolves aliases from the operating system's credential store."""

    name = "keyring"

    def __init__(self, service_name: str = _SERVICE_NAME):
        # Import eagerly at construction so a missing dependency fails loudly
        # here, rather than silently returning None on every lookup later.
        try:
            import keyring  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "The 'keyring' package is required for the keyring secret backend. "
                "Install it with: pip install auro-runtime[keyring]"
            ) from e
        self._service_name = service_name

    def get(self, alias: str) -> str | None:
        import keyring
        from keyring.errors import KeyringError

        try:
            value = keyring.get_password(self._service_name, alias)
        except KeyringError as e:
            # A locked or unavailable keychain is misconfiguration, not a
            # missing alias — say so instead of returning a confusing None.
            raise RuntimeError(f"OS keychain unavailable: {e}") from e
        if value is not None and value.strip():
            return value.strip()
        return None

    def list_aliases(self) -> list[str]:
        # The keyring API has no portable enumeration across backends.
        return []

    def set(self, alias: str, value: str) -> None:
        """
        Store a secret. Not part of the SecretBackend protocol — the runtime
        never writes secrets during a run. Provided so setup tooling and the
        user can populate the keychain without leaving Python.
        """
        import keyring

        keyring.set_password(self._service_name, alias, value)
