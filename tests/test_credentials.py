"""
Credential resolution and the alias-parameter delivery path.

The security property under test throughout: **the model must be able to name a
secret without ever seeing it.** A resolved value must never appear in a tool
result, an error message, or the audit trail — only the alias name may.
"""

import sys
from types import SimpleNamespace

import pytest

from auro_runtime import secrets as secrets_mod
from auro_runtime.executor import execute
from auro_runtime.guards import get_guard_registry

SECRET_VALUE = "ghp_" + "a" * 36
ALIAS = "test_probe_token"
MODEL_SECRET = "model_provider_secret_" + "z" * 24
MODEL_ALIAS = "anthropic_provider"


@pytest.fixture
def env_secret(monkeypatch):
    """Configure one secret via the default env backend."""
    monkeypatch.setenv(f"AURO_SECRET_{ALIAS.upper()}", SECRET_VALUE)
    return ALIAS


@pytest.fixture(autouse=True)
def _no_backend_selected(monkeypatch):
    """Most tests should exercise the default (env-only) path."""
    monkeypatch.delenv("AURO_SECRET_BACKEND", raising=False)


# --- Keyring backend: real round trip against the OS credential store --------

# Deliberately NOT the runtime's own "auro-runtime" service name. These tests
# write and delete, and must never be able to touch a real credential the user
# has stored for actual use.
_TEST_SERVICE = "auro-runtime-test-probe"


def _usable_keyring_reason() -> str | None:
    """Return None only if the selected backend can complete a real round trip."""
    try:
        import keyring
    except ImportError:
        return "keyring is not installed — the keyring backend is NOT covered on this machine"

    probe_alias = "availability_probe"
    try:
        from keyring.backends.fail import Keyring as FailKeyring

        if isinstance(keyring.get_keyring(), FailKeyring):
            return "no usable OS keyring backend — the keyring backend is NOT covered on this machine"
        keyring.set_password(_TEST_SERVICE, probe_alias, "availability-probe")
        if keyring.get_password(_TEST_SERVICE, probe_alias) != "availability-probe":
            return "OS keyring did not round-trip a probe — the keyring backend is NOT covered on this machine"
    except Exception as e:  # pragma: no cover - backend and OS specific
        return f"OS keyring is unavailable — the keyring backend is NOT covered on this machine: {e}"
    finally:
        try:
            keyring.delete_password(_TEST_SERVICE, probe_alias)
        except Exception:
            pass
    return None


_KEYRING_SKIP = _usable_keyring_reason()

requires_keyring = pytest.mark.skipif(_KEYRING_SKIP is not None, reason=_KEYRING_SKIP or "")


@requires_keyring
class TestKeyringBackendRoundTrip:
    """
    The success path of the keyring backend, exercised against the real OS
    credential store.

    Until 2026-07-26 every keyring assertion in this suite covered the *absent*
    case: backend selected but module missing, and the lazy-import check. `get`,
    `set` and `list_aliases` had no success assertion at all, and `keyring` was
    not installed in the dev environment — so the suite reported green on a
    machine where the integration could not function, with nothing marking it
    untested.

    These tests are skipped rather than silently passed when keyring is
    unavailable, so an uncovered machine says so in the summary line.
    """

    @pytest.fixture
    def probe(self):
        """A backend on an isolated service name, cleaned up even on failure."""
        import keyring

        from auro_runtime.secrets_backends.keyring_backend import KeyringSecretBackend

        alias = "roundtrip_probe"
        backend = KeyringSecretBackend(service_name=_TEST_SERVICE)
        try:
            yield backend, alias
        finally:
            try:
                keyring.delete_password(_TEST_SERVICE, alias)
            except Exception:
                pass

    def test_stored_value_round_trips(self, probe):
        backend, alias = probe
        value = "probe_value_" + "q" * 20
        backend.set(alias, value)
        assert backend.get(alias) == value

    def test_missing_alias_returns_none_rather_than_raising(self, probe):
        backend, _ = probe
        assert backend.get("alias_that_was_never_stored_xyz") is None

    def test_deleted_alias_stops_resolving(self, probe):
        import keyring

        backend, alias = probe
        backend.set(alias, "transient")
        assert backend.get(alias) == "transient"
        keyring.delete_password(_TEST_SERVICE, alias)
        assert backend.get(alias) is None

    def test_whitespace_only_value_is_treated_as_absent(self, probe):
        """`get` strips and treats blank as missing, so a blank entry must not
        resolve to an empty-but-present credential."""
        backend, alias = probe
        backend.set(alias, "   ")
        assert backend.get(alias) is None

    def test_list_aliases_is_empty_by_design(self, probe):
        """Documented limitation: keyring has no portable enumeration. Pinned so
        that if it ever starts returning entries, that is a deliberate change."""
        backend, _ = probe
        assert backend.list_aliases() == []


# --- Resolution ---------------------------------------------------------------


def test_env_backend_resolves_an_alias(env_secret):
    assert secrets_mod.get_secret(env_secret) == SECRET_VALUE


def test_unknown_alias_returns_none():
    assert secrets_mod.get_secret("no_such_alias_xyz") is None


def test_env_lookup_is_case_insensitive_on_the_alias(env_secret):
    assert secrets_mod.get_secret(env_secret.upper()) == SECRET_VALUE


@pytest.mark.parametrize("bad", ["", "../etc/passwd", "a/b", "a.b", "a b", "a;b"])
def test_path_like_aliases_are_rejected(bad):
    """Aliases are identifiers, not paths."""
    assert secrets_mod.get_secret(bad) is None


def test_request_scoped_secrets_take_priority(env_secret):
    secrets_mod.set_request_secrets({env_secret: "request_scoped_value"})
    try:
        assert secrets_mod.get_secret(env_secret) == "request_scoped_value"
    finally:
        secrets_mod.clear_request_secrets()
    assert secrets_mod.get_secret(env_secret) == SECRET_VALUE


def test_list_aliases_reports_names_not_values(env_secret):
    aliases = secrets_mod.list_secret_aliases()
    assert env_secret in aliases
    assert SECRET_VALUE not in repr(aliases)


# --- Backend selection --------------------------------------------------------


def test_default_selects_no_extra_backend():
    assert secrets_mod.get_backend() is None


def test_env_is_an_accepted_explicit_value(monkeypatch):
    monkeypatch.setenv("AURO_SECRET_BACKEND", "env")
    assert secrets_mod.get_backend() is None


def test_unknown_backend_name_raises(monkeypatch):
    monkeypatch.setenv("AURO_SECRET_BACKEND", "not_a_backend")
    with pytest.raises(ValueError, match="Unknown"):
        secrets_mod.get_backend()


def test_selecting_an_unusable_backend_fails_loudly_not_silently(monkeypatch):
    """
    Explicit selection must distinguish a missing dependency from an alias that
    simply does not exist.
    """
    monkeypatch.setenv("AURO_SECRET_BACKEND", "keyring")
    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(RuntimeError):
        secrets_mod.get_backend()


def test_backends_are_imported_lazily():
    """Importing the package must not require any optional dependency."""
    import subprocess
    import sys

    code = (
        "import sys; import auro_runtime.secrets; "
        "assert 'keyring' not in sys.modules, 'keyring imported eagerly'; "
        "print('ok')"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


# --- Model-provider credentials ----------------------------------------------


@pytest.fixture
def fake_anthropic(monkeypatch):
    """Capture SDK construction and requests without making a network call."""
    captured = {}

    class _Messages:
        def create(self, **kwargs):
            captured["request"] = kwargs
            return SimpleNamespace(content=[SimpleNamespace(text="model response")])

    class _Client:
        def __init__(self, *, api_key):
            captured["api_key"] = api_key
            self.messages = _Messages()

    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=_Client))
    return captured


def test_anthropic_backend_resolves_configured_alias(monkeypatch, fake_anthropic):
    from auro_runtime.audit import set_audit_collector
    from auro_runtime.models.anthropic_backend import AnthropicBackend

    monkeypatch.setenv("AURO_ANTHROPIC_API_KEY_ALIAS", MODEL_ALIAS)
    monkeypatch.setenv(f"AURO_SECRET_{MODEL_ALIAS.upper()}", MODEL_SECRET)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "compatibility_key_must_not_win")

    audit_events = []
    set_audit_collector(audit_events)
    try:
        result = AnthropicBackend().generate("system", "user")
    finally:
        set_audit_collector(None)

    assert result == "model response"
    assert fake_anthropic["api_key"] == MODEL_SECRET
    assert MODEL_SECRET not in repr(fake_anthropic["request"])
    assert MODEL_SECRET not in result
    assert MODEL_SECRET not in repr(audit_events)


def test_anthropic_backend_uses_request_scoped_alias(monkeypatch, fake_anthropic):
    from auro_runtime.models.anthropic_backend import AnthropicBackend

    monkeypatch.setenv("AURO_ANTHROPIC_API_KEY_ALIAS", MODEL_ALIAS)
    secrets_mod.set_request_secrets({MODEL_ALIAS: MODEL_SECRET})
    try:
        result = AnthropicBackend().generate("system", "user")
    finally:
        secrets_mod.clear_request_secrets()

    assert result == "model response"
    assert fake_anthropic["api_key"] == MODEL_SECRET


def test_anthropic_backend_alias_fails_closed(monkeypatch, fake_anthropic):
    from auro_runtime.models.anthropic_backend import AnthropicBackend

    raw_fallback = "raw_fallback_" + "q" * 24
    monkeypatch.setenv("AURO_ANTHROPIC_API_KEY_ALIAS", "missing_model_alias")
    monkeypatch.setenv("ANTHROPIC_API_KEY", raw_fallback)

    with pytest.raises(RuntimeError) as exc_info:
        AnthropicBackend().generate("system", "user")

    assert "missing_model_alias" in str(exc_info.value)
    assert raw_fallback not in str(exc_info.value)
    assert "api_key" not in fake_anthropic


def test_anthropic_backend_retains_environment_compatibility(monkeypatch, fake_anthropic):
    from auro_runtime.models.anthropic_backend import AnthropicBackend

    monkeypatch.delenv("AURO_ANTHROPIC_API_KEY_ALIAS", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", MODEL_SECRET)

    assert AnthropicBackend().generate("system", "user") == "model response"
    assert fake_anthropic["api_key"] == MODEL_SECRET


# --- resolve_secret never leaks ----------------------------------------------


def test_resolve_secret_reports_presence_without_the_value(env_secret, registry):
    from runtime_tools.credential_tools import resolve_secret

    result = resolve_secret(env_secret)
    assert result["resolved"] is True
    assert SECRET_VALUE not in repr(result)


def test_resolve_secret_on_missing_alias(registry):
    from runtime_tools.credential_tools import resolve_secret

    result = resolve_secret("definitely_not_configured")
    assert result["resolved"] is False


# --- http_request auth_alias --------------------------------------------------


def test_http_request_injects_the_resolved_token(env_secret, registry, monkeypatch):
    from runtime_tools import http_request_tools

    captured = {}

    class _Resp:
        status_code = 200
        headers = {"Content-Type": "text/plain"}
        text = "ok"

    def fake_get(url, headers=None, timeout=None):
        captured["headers"] = headers
        return _Resp()

    import requests

    monkeypatch.setattr(requests, "get", fake_get)
    result = http_request_tools.http_request("https://example.com", auth_alias=env_secret)

    assert captured["headers"]["Authorization"] == f"Bearer {SECRET_VALUE}"
    assert SECRET_VALUE not in repr(result), "resolved secret must not appear in the tool result"


def test_http_request_auth_scheme_is_honoured(env_secret, registry, monkeypatch):
    from runtime_tools import http_request_tools

    captured = {}

    class _Resp:
        status_code = 200
        headers = {}
        text = "ok"

    def fake_get(url, headers=None, timeout=None):
        captured["headers"] = headers
        return _Resp()

    import requests

    monkeypatch.setattr(requests, "get", fake_get)
    http_request_tools.http_request("https://example.com", auth_alias=env_secret, auth_scheme="Token")
    assert captured["headers"]["Authorization"].startswith("Token ")


def test_http_request_rejects_an_unknown_auth_scheme(env_secret, registry):
    from runtime_tools.http_request_tools import http_request

    result = http_request("https://example.com", auth_alias=env_secret, auth_scheme="Weird")
    assert "Unsupported auth_scheme" in result["error"]


def test_http_request_unconfigured_alias_names_the_alias_not_the_value(registry):
    from runtime_tools.http_request_tools import http_request

    result = http_request("https://example.com", auth_alias="not_configured_alias")
    assert "not_configured_alias" in result["error"]
    assert "is not configured" in result["error"]


def test_http_request_without_auth_alias_is_unchanged(registry, monkeypatch):
    from runtime_tools import http_request_tools

    captured = {}

    class _Resp:
        status_code = 200
        headers = {}
        text = "ok"

    def fake_get(url, headers=None, timeout=None):
        captured["headers"] = headers
        return _Resp()

    import requests

    monkeypatch.setattr(requests, "get", fake_get)
    http_request_tools.http_request("https://example.com")
    assert not (captured["headers"] or {}).get("Authorization")


# --- send_notification webhook_url_alias --------------------------------------


def test_send_notification_resolves_the_url_alias(registry, monkeypatch):
    """Slack and Discord webhook URLs contain the token, so the URL is the secret."""
    from runtime_tools import notification_tools

    secret_url = "https://hooks.slack.com/services/T000/B000/" + "x" * 24
    monkeypatch.setenv("AURO_SECRET_SLACK_HOOK", secret_url)

    captured = {}

    class _Resp:
        status_code = 200
        text = "ok"

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        return _Resp()

    import requests

    monkeypatch.setattr(requests, "post", fake_post)
    result = notification_tools.send_notification(message="hi", webhook_url_alias="slack_hook")

    assert captured["url"] == secret_url
    assert secret_url not in repr(result), "resolved webhook URL must not appear in the result"


def test_send_notification_requires_a_url_or_an_alias(registry):
    from runtime_tools.notification_tools import send_notification

    result = send_notification(message="hi")
    assert result["sent"] is False
    assert "webhook_url_alias" in result["error"]


# --- The guard that enforces the convention -----------------------------------


def test_guard_blocks_a_raw_token_nested_in_headers(make_guard_context):
    """
    The common shape of the mistake. Before alias params existed this guard
    could not fire on any legitimate argument of any registered tool.
    """
    guard = get_guard_registry()["check_no_raw_credentials"]
    ctx = make_guard_context(
        "http_request",
        {"url": "https://x", "headers": {"Authorization": f"Bearer {SECRET_VALUE}"}},
    )
    verdict = guard(ctx)
    assert verdict is not None
    assert verdict.allowed is False
    assert verdict.code == "raw_credential"


def test_guard_allows_the_alias_parameter(make_guard_context):
    guard = get_guard_registry()["check_no_raw_credentials"]
    ctx = make_guard_context("http_request", {"url": "https://x", "auth_alias": "github_token"})
    assert guard(ctx) is None


def test_guard_blocks_a_top_level_raw_credential(make_guard_context):
    guard = get_guard_registry()["check_no_raw_credentials"]
    ctx = make_guard_context("http_request", {"url": "https://x", "api_key": SECRET_VALUE})
    assert guard(ctx) is not None


def test_real_policy_refuses_a_raw_authorization_header(make_tool_call, enforceable_rules, registry):
    """End of the chain: the shipped rules block it at enforcement level."""
    call = make_tool_call(
        "http_request",
        {"url": "https://example.com", "headers": {"Authorization": f"Bearer {SECRET_VALUE}"}},
    )
    result = execute(call, allowed_tools={"http_request"}, policy_rules=enforceable_rules)
    assert result.success is False
    assert "raw" in result.error.lower() or "alias" in result.error.lower()


def test_alias_use_survives_the_real_policy_chain(env_secret, make_tool_call,
                                                  enforceable_rules, registry,
                                                  audit_events, monkeypatch):
    """Using an alias must not be blocked, and must not leak into the audit."""
    class _Resp:
        status_code = 200
        headers = {}
        text = "ok"

    import requests

    monkeypatch.setattr(requests, "get", lambda url, headers=None, timeout=None: _Resp())

    call = make_tool_call("http_request", {"url": "https://example.com", "auth_alias": env_secret})
    result = execute(call, allowed_tools={"http_request"}, policy_rules=enforceable_rules)

    assert result.success is True, result.error
    assert SECRET_VALUE not in repr(audit_events), "secret leaked into the audit trail"
    assert SECRET_VALUE not in repr(result)
