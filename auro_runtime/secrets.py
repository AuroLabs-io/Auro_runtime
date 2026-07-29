"""
Credential resolution.

**auro-runtime does not store your secrets.** It resolves an alias to a value
from a source you configure, and never returns that value to the model.

Resolution order:

  1. Request-scoped secrets, if an embedder supplied them for this run.
  2. Environment variables — AURO_SECRET_<ALIAS>. Always consulted, so a value
     in the environment overrides the configured store. Zero dependencies.
  3. The backend named by AURO_SECRET_BACKEND, if any.

Available backends:

  env      (default, always active)  Reads values already present in the
           process environment. The deploying system remains responsible for
           storage and injection.
  keyring  Delegates to the backend selected by Python's keyring package.
           Storage and unlock behavior depend on that backend. Extra: [keyring]

Embedding applications may resolve credentials in their own layer and supply
them through the request-scoped API. SecretBackend remains an internal seam
between the built-in sources, not a public plugin interface.

Choosing a backend that is not usable raises at construction rather than
returning None. "The store is broken" and "that alias does not exist" must not
look the same to a caller.
"""

import os
from contextvars import ContextVar

from auro_runtime.secrets_backends.base import SecretBackend
from auro_runtime.secrets_backends.env_backend import EnvSecretBackend

__all__ = [
    "get_secret",
    "get_backend",
    "list_secret_aliases",
    "set_request_secrets",
    "clear_request_secrets",
]

_BACKEND_ENV = "AURO_SECRET_BACKEND"

# Request-scoped secrets, set by an embedder for the duration of one run and
# cleared in a finally. Never persisted.
_request_secrets: ContextVar[dict[str, str] | None] = ContextVar("request_secrets", default=None)

_env_backend = EnvSecretBackend()


def get_backend() -> SecretBackend | None:
    """
    Construct the backend named by AURO_SECRET_BACKEND, or None if unset.

    Backends are imported lazily so the package loads with no optional
    dependency installed, and raise on construction if they cannot work.
    """
    name = (os.environ.get(_BACKEND_ENV) or "").strip().lower()
    if not name or name == "env":
        return None  # env is already consulted unconditionally

    if name == "keyring":
        from auro_runtime.secrets_backends.keyring_backend import KeyringSecretBackend

        return KeyringSecretBackend()
    raise ValueError(
        f"Unknown {_BACKEND_ENV} '{name}'. Expected 'env' or 'keyring'."
    )


def _is_safe_alias(alias: str) -> bool:
    """Aliases are identifiers, not paths — keep them boring."""
    return bool(alias) and alias.replace("_", "").replace("-", "").isalnum()


def get_secret(alias: str) -> str | None:
    """
    Resolve a secret by alias, or None if no configured source has it.

    Never log the return value. Callers that surface results to a model must
    return only whether the alias resolved, never the value itself.
    """
    if not _is_safe_alias(alias):
        return None

    request_secrets = _request_secrets.get()
    if request_secrets:
        value = request_secrets.get(alias)
        if value is not None and str(value).strip():
            return str(value).strip()

    value = _env_backend.get(alias)
    if value is not None:
        return value

    backend = get_backend()
    if backend is not None:
        return backend.get(alias)
    return None


def list_secret_aliases() -> list[str]:
    """Alias names known to the active sources. Never exposes values."""
    aliases = set(_env_backend.list_aliases())
    request_secrets = _request_secrets.get()
    if request_secrets:
        aliases.update(request_secrets)
    try:
        backend = get_backend()
        if backend is not None:
            aliases.update(backend.list_aliases())
    except Exception:
        # Enumeration is best-effort; a broken optional backend must not break
        # a caller that only wanted to list what it could see.
        pass
    return sorted(aliases)


def set_request_secrets(secrets: dict[str, str] | None) -> None:
    """
    Supply secrets for the current run only. For embedders that resolve
    credentials in their own layer and pass them in per request.
    """
    _request_secrets.set(secrets)


def clear_request_secrets() -> None:
    """Clear request-scoped secrets. Call in a finally after a run."""
    try:
        _request_secrets.set(None)
    except LookupError:
        pass
