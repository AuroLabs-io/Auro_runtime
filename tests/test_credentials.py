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


class _Resp:
    status_code = 200
    headers = {"Content-Type": "text/plain"}
    text = "ok"


def _capture_outbound(monkeypatch):
    """Stub the egress boundary and return the dict it records headers into.

    Patched at `guarded_request`, which is the seam the tool actually calls.
    These are credential tests: they prove the Authorization header is built
    and the secret does not leak into the result. Destination checking is
    deliberately out of scope here and is covered by its own suites.
    """
    from runtime_tools import http_request_tools

    captured: dict = {}

    def fake(method, url, *, headers=None, data=None, timeout=None):
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = headers
        return _Resp()

    monkeypatch.setattr(http_request_tools, "guarded_request", fake)
    return captured


def test_http_request_injects_the_resolved_token(env_secret, registry, monkeypatch):
    from runtime_tools import http_request_tools

    captured = _capture_outbound(monkeypatch)
    result = http_request_tools.http_request("https://example.com", auth_alias=env_secret)

    assert captured["headers"]["Authorization"] == f"Bearer {SECRET_VALUE}"
    assert SECRET_VALUE not in repr(result), "resolved secret must not appear in the tool result"


def test_http_request_auth_scheme_is_honoured(env_secret, registry, monkeypatch):
    from runtime_tools import http_request_tools

    captured = _capture_outbound(monkeypatch)
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

    captured = _capture_outbound(monkeypatch)
    http_request_tools.http_request("https://example.com")
    assert not (captured["headers"] or {}).get("Authorization")


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
    result = execute(call, allowed_tools={"http_request"}, policy_rules=enforceable_rules, run_history=[])
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
    result = execute(call, allowed_tools={"http_request"}, policy_rules=enforceable_rules, run_history=[])

    assert result.success is True, result.error
    assert SECRET_VALUE not in repr(audit_events), "secret leaked into the audit trail"
    assert SECRET_VALUE not in repr(result)


# --- Refusals must not log what they refused ---------------------------------
#
# The alias path above is the happy case. The dangerous one is the refusal: a
# guard finds a raw credential, the call is blocked, and the audit record of the
# block carries the credential. Redaction before that write has two inputs, and
# only one of them is enough on its own.

# Deliberately matches no SECRET_PATTERNS entry, and sits under a key that is
# not in SENSITIVE_KEYS. Neither pass of the name-and-shape redaction can see
# it, so it is redacted only if the guard says where it found it.
BESPOKE_CREDENTIAL = "bespoke-" + "7" * 32


def test_a_refused_raw_credential_is_not_logged_in_the_clear(
    make_tool_call, enforceable_rules, registry, audit_events
):
    """
    A refusal must not record what it refused.

    Two independent mechanisms now cover this: the guard's
    metadata["matched_fields"] addresses the exact field, and `client_id` is in
    SENSITIVE_KEYS so the name-based pass catches it too. Before 2026-08-06 only
    the first applied, and this test is written so it would fail if BOTH were
    removed rather than proving either one individually — the targeted pass is
    pinned separately by
    test_targeted_redaction_reaches_a_key_the_name_pass_does_not.

    Kept end-to-end deliberately: this is the test that caught the audit
    disclosure opened by tightening the argument schemas.
    """
    call = make_tool_call(
        "http_request",
        {"url": "https://example.com", "client_id": BESPOKE_CREDENTIAL},
    )
    result = execute(call, allowed_tools={"http_request"},
                     policy_rules=enforceable_rules, run_history=[])

    assert result.success is False, "precondition: the call must be refused"
    assert BESPOKE_CREDENTIAL not in repr(audit_events), (
        "the refused credential reached the audit log in the clear"
    )
    # Positive control. Without this the test also passes when nothing is
    # recorded at all, which would make the assertion above vacuous.
    assert "example.com" in repr(audit_events), (
        "arguments are not being recorded, so the absence above proves nothing"
    )


def test_credential_key_sets_do_not_diverge():
    """
    Every key the credential guard will refuse a call over must also be
    redactable by name.

    These two sets drifted apart once already: three cloud identifiers were in
    the guard's set and not the sanitizer's, on the reasoning that the guard's
    matched_fields would cover them. That reasoning held only where a guard
    actually runs. It does not hold on the argument-validation refusal path,
    which fires before any guard, and it did not hold for a field nested inside
    a list. Both were live plaintext disclosures.

    Stated as containment rather than equality: SENSITIVE_KEYS is allowed to be
    broader (it carries `key`, `credential` and others the guard does not act
    on). The direction that must never regress is a guard key with no name-based
    cover.
    """
    from auro_runtime.guards import _RAW_CREDENTIAL_KEYS
    from auro_runtime.sanitization import SENSITIVE_KEYS

    uncovered = sorted(k for k in _RAW_CREDENTIAL_KEYS if k not in SENSITIVE_KEYS)
    assert not uncovered, (
        f"{uncovered} would be refused by check_no_raw_credentials but cannot be "
        f"redacted by name. On any refusal path that runs before the guard, the "
        f"value reaches the audit log in the clear."
    )


def test_a_pre_guard_refusal_does_not_log_a_credential(
    make_tool_call, registry, audit_events
):
    """
    Argument-schema validation refuses before any guard runs, and writes the
    rejected args to the audit log. No verdict exists on that path, so no
    matched_fields exist either — the name-based pass is the only cover.

    Uses UNRESTRICTED so that no guard runs at all: if this passes, it passes
    because the sanitizer covered the key, not because a guard rescued it.
    """
    from auro_runtime.executor import UNRESTRICTED

    # `message` is required and absent, so validation fails for a reason that
    # has nothing to do with the credential riding along beside it.
    call = make_tool_call("echo", {"client_id": BESPOKE_CREDENTIAL})
    result = execute(call, allowed_tools={"echo"},
                     policy_rules=UNRESTRICTED, run_history=[])

    assert result.success is False, "precondition: the call must be refused"
    assert not any(e.get("event") == "policy_guard_check" for e in audit_events), (
        "precondition: no guard may have run, or this proves nothing about the "
        "pre-guard path"
    )
    assert BESPOKE_CREDENTIAL not in repr(audit_events), (
        "a credential reached the audit log through the argument-validation "
        "refusal path, which no guard covers"
    )
    # Positive control: the refusal IS being recorded, so the absence above is
    # redaction rather than silence.
    assert any(e.get("event") == "argument_validation_failed" for e in audit_events), (
        "the refusal was not audited at all, so the assertion above is vacuous"
    )


def test_targeted_redaction_reaches_a_key_the_name_pass_does_not():
    """
    Pins the matched_fields pass on its own.

    Once every guard key is also a sanitizer key, no end-to-end guard test can
    isolate the targeted pass any more — the name pass would rescue it. So drive
    redact_for_audit directly with a key that is deliberately outside
    SENSITIVE_KEYS, where the field path is the only thing that can work.
    """
    from auro_runtime.guards import redact_for_audit
    from auro_runtime.sanitization import SENSITIVE_KEYS

    assert "project_ref" not in SENSITIVE_KEYS, "probe key must be uncovered by name"

    out = redact_for_audit({"project_ref": BESPOKE_CREDENTIAL}, ["project_ref"])
    assert BESPOKE_CREDENTIAL not in repr(out), (
        "the targeted pass did not redact the field its input named"
    )

    # Control: without the matched_fields input the same value survives, so the
    # assertion above is about the targeted pass and not about blanket scrubbing.
    kept = redact_for_audit({"project_ref": BESPOKE_CREDENTIAL}, None)
    assert BESPOKE_CREDENTIAL in repr(kept)


def test_credential_header_spellings_are_redacted_by_name():
    """
    `x-api-key` and `x-auth-token` carry credentials and match no secret
    pattern, so the name-based pass is the only thing that catches them when a
    call is refused for an unrelated reason and the verdict supplies no
    matched_fields.
    """
    from auro_runtime.sanitization import sanitize_value

    scrubbed = sanitize_value(
        {"headers": {"x-api-key": BESPOKE_CREDENTIAL, "x-auth-token": BESPOKE_CREDENTIAL}}
    )
    assert BESPOKE_CREDENTIAL not in repr(scrubbed)

    # Control: an innocuous header keeps its value, so the assertion above is
    # about these two names rather than about everything being scrubbed.
    kept = sanitize_value({"headers": {"x-request-id": BESPOKE_CREDENTIAL}})
    assert BESPOKE_CREDENTIAL in repr(kept)


@pytest.mark.parametrize(
    "guard_name, args",
    [
        ("check_no_raw_credentials",
         {"url": "https://x", "client_id": BESPOKE_CREDENTIAL}),
        ("check_no_secrets_in_args",
         {"url": "https://x", "headers": {"Authorization": f"Bearer {SECRET_VALUE}"}}),
    ],
)
def test_redacting_verdicts_carry_the_field_the_executor_reads(
    guard_name, args, make_guard_context
):
    """
    Pins the contract behind the test above. A verdict whose code is in
    REDACTING_VERDICT_CODES triggers the targeted redaction pass, and
    metadata["matched_fields"] is that pass's only input. A guard that finds a
    secret and does not say where causes the executor to log it.

    Parametrized over every guard that can emit one of those codes, so a third
    code cannot join the set without a guard here failing to supply the key.
    """
    from auro_runtime.executor import REDACTING_VERDICT_CODES

    guard = get_guard_registry()[guard_name]
    verdict = guard(make_guard_context("http_request", args))

    assert verdict is not None, f"precondition: {guard_name} must fire on this input"
    assert verdict.code in REDACTING_VERDICT_CODES
    assert verdict.metadata and verdict.metadata.get("matched_fields"), (
        f"{guard_name} emits '{verdict.code}', which triggers targeted redaction, "
        f"but supplies no matched_fields for it to act on"
    )
    for segments in verdict.metadata["matched_fields"]:
        assert isinstance(segments, list) and segments, (
            f"{guard_name} supplied {segments!r}. matched_fields carries "
            f"structured segment paths; a flattened string would have to be "
            f"re-parsed, which is the ambiguity this contract removed"
        )


def test_the_contract_check_fails_when_a_guard_supplies_the_wrong_key():
    """Negative control for the parametrized test above.

    With every real guard compliant, that test passes whether or not its
    assertion is capable of failing. This drives the same two conditions over a
    verdict shaped like the original defect — the guard finding the field and
    reporting it under a key the executor does not read — and requires them to
    reject it.
    """
    from auro_runtime.executor import REDACTING_VERDICT_CODES
    from auro_runtime.guards import GuardVerdict

    defective = GuardVerdict(
        allowed=False,
        message="found one",
        code="raw_credential",
        # Exactly the 2026-08-03 defect: the path is known and handed over
        # under a name nothing consumes.
        metadata={"key": "client_id", "field": "items[0].client_id"},
    )

    assert defective.code in REDACTING_VERDICT_CODES
    assert not (defective.metadata and defective.metadata.get("matched_fields")), (
        "the contract assertion would have accepted a verdict that supplies no "
        "matched_fields, so the parametrized test above proves nothing"
    )

    # The other half: supplying the key but in the old flattened form. Every
    # real guard emits lists, so without this the shape assertion in the
    # parametrized test could be weakened to a null check and nothing would
    # notice.
    flattened = GuardVerdict(
        allowed=False, message="found one", code="raw_credential",
        metadata={"matched_fields": ["items[0].client_id"]},
    )
    assert not all(
        isinstance(segments, list) and segments
        for segments in flattened.metadata["matched_fields"]
    ), (
        "the shape assertion would have accepted a flattened string, which is "
        "the ambiguous format this contract replaced"
    )


# --- the targeted pass, across every shape a producer can emit ---------------


@pytest.mark.parametrize("args, segments, shape", [
    ({"project_ref": BESPOKE_CREDENTIAL},
     [["project_ref"]], "top level"),
    ({"outer": {"project_ref": BESPOKE_CREDENTIAL}},
     [["outer", "project_ref"]], "plain nesting"),
    ({"items": [{"project_ref": BESPOKE_CREDENTIAL}]},
     [["items", 0, "project_ref"]], "inside a list"),
    ({"items": [[{"project_ref": BESPOKE_CREDENTIAL}]]},
     [["items", 0, 0, "project_ref"]], "list inside a list"),
    ({"a.b": {"project_ref": BESPOKE_CREDENTIAL}},
     [["a.b", "project_ref"]], "a key containing a dot"),
])
def test_the_targeted_pass_reaches_every_shape(args, segments, shape):
    """
    The reopen of 2026-08-05 was the `inside a list` row: paths were flattened
    to strings and split on `.`, so an index segment never resolved and the pass
    silently no-opped.

    The `a key containing a dot` row is why fixing the parser would not have
    been enough. `{"a": {"b": ...}}` and `{"a.b": ...}` flatten to the identical
    string, so the format was not injective and no parser however careful could
    tell them apart. Carrying structure removes the grammar entirely.

    Every row uses a key outside SENSITIVE_KEYS, so only the targeted pass can
    do the work — the name-based pass would otherwise rescue the assertion and
    hide a broken pass.
    """
    from auro_runtime.guards import redact_for_audit
    from auro_runtime.sanitization import SENSITIVE_KEYS

    assert "project_ref" not in SENSITIVE_KEYS, "probe key must be uncovered by name"

    out = redact_for_audit(args, segments)
    assert BESPOKE_CREDENTIAL not in repr(out), f"{shape}: not redacted -> {out!r}"

    kept = redact_for_audit(args, None)
    assert BESPOKE_CREDENTIAL in repr(kept), (
        f"{shape}: the control failed — the value is being removed by something "
        f"other than the targeted pass, so this row proves nothing"
    )


@pytest.mark.parametrize("segments", [
    [["nope", "missing"]],          # first segment absent
    [["nope", "harmless"]],         # prefix absent, LAST segment exists at root
    [["items", 7, "project_ref"]],  # index out of range
    [["items", 0, "absent"]],       # every segment but the last resolves
    [["items", "0", "project_ref"]],  # string where an index belongs
    [[]],                            # empty path
])
def test_an_unresolvable_path_redacts_everything_rather_than_skipping(segments):
    """The class closure, and the half that outlives this particular bug.

    A targeted pass that cannot find its target has not decided the value is
    safe — it has failed to look, and those two outcomes were previously
    indistinguishable in the output. Any future producer that emits a path this
    consumer cannot walk now over-redacts instead of leaking, so the next
    instance of this class costs audit detail rather than a credential.

    Fail-closed per D-038, and visibly: an all-redacted record is itself the
    signal that something is wrong with the guard that produced the path.
    """
    from auro_runtime.guards import redact_for_audit

    args = {"items": [{"project_ref": BESPOKE_CREDENTIAL}], "harmless": "keep-me"}
    out = redact_for_audit(args, segments)

    assert BESPOKE_CREDENTIAL not in repr(out)
    assert "keep-me" not in repr(out), (
        "the fallback redacted the named target but not the rest, so a value "
        "under a path nobody named would still have leaked"
    )


def test_a_resolvable_path_does_not_trigger_the_fallback():
    """Control: the over-redaction fires on failure only, not on every call."""
    from auro_runtime.guards import redact_for_audit

    out = redact_for_audit(
        {"items": [{"project_ref": BESPOKE_CREDENTIAL}], "harmless": "keep-me"},
        [["items", 0, "project_ref"]],
    )

    assert BESPOKE_CREDENTIAL not in repr(out)
    assert "keep-me" in repr(out), (
        "a resolvable path triggered the blanket fallback, which would destroy "
        "audit detail on every redacting verdict"
    )


def test_the_guard_and_the_redactor_agree_on_a_nested_credential(make_guard_context):
    """End to end: the path the guard emits is one the consumer can walk.

    The original defect was not that either half was wrong on its own — it was
    that the guard produced a format its own consumer could not parse. This
    composes them rather than testing each in isolation, which is where the
    disagreement lived.
    """
    from auro_runtime.guards import redact_for_audit, get_guard_registry

    args = {"url": "https://x", "items": [{"client_id": BESPOKE_CREDENTIAL}],
            "note": "ordinary detail"}
    verdict = get_guard_registry()["check_no_raw_credentials"](
        make_guard_context("http_request", args)
    )

    assert verdict is not None, "precondition: the guard must fire"
    out = redact_for_audit(args, verdict.metadata["matched_fields"])

    assert BESPOKE_CREDENTIAL not in repr(out)
    assert "ordinary detail" in repr(out), (
        "unrelated argument content did not survive redaction, so the audit "
        "record loses the context an operator needs"
    )
