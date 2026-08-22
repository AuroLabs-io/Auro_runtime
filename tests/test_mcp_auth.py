"""
Bearer-token admission for the streamable-HTTP transport.

This is the runtime's only network-exposed authentication surface. The README
documents it in three places; until these tests existed nothing proved it worked
in either direction.

Two levels are covered, because the documented property spans two of them:

* `_ApiKeyTokenVerifier.verify_token` decides whether a token is the configured
  one. It never sees a header.
* `BearerAuthBackend.authenticate` is what parses the `Authorization` header and
  is therefore where "absent or malformed header" is actually decided. It is the
  layer the verifier is mounted into in production.

Neither level drives a full ASGI request, so nothing here proves a 401 reaches a
client -- only that admission is refused.

`_MCP_API_KEY` is read at import time, so `monkeypatch.setenv` does nothing for
these tests. Patch the module attribute instead.
"""

import asyncio
import os
import subprocess
import sys

import pytest

from starlette.requests import HTTPConnection

from auro_runtime import mcp_server

CONFIGURED_TOKEN = "test-only-placeholder-key"


# --- Helpers ---------------------------------------------------------------


def verify(token: str):
    """Run the real verifier against one token."""
    return asyncio.run(mcp_server._ApiKeyTokenVerifier().verify_token(token))


def authenticate(header_value: str | None):
    """
    Drive the real BearerAuthBackend the server mounts, with `header_value` as
    the raw Authorization header.

    Headers go on the wire as bytes and Starlette decodes them as latin-1, so
    the header is encoded that way here rather than as UTF-8. That difference is
    the whole reason the non-ASCII case below exists.
    """
    from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend

    headers = []
    if header_value is not None:
        headers.append((b"authorization", header_value.encode("latin-1")))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": headers,
    }
    backend = BearerAuthBackend(mcp_server._ApiKeyTokenVerifier())
    return asyncio.run(backend.authenticate(HTTPConnection(scope)))


@pytest.fixture
def configured_key(monkeypatch):
    """The ordinary deployment: an ASCII key is configured."""
    monkeypatch.setattr(mcp_server, "_MCP_API_KEY", CONFIGURED_TOKEN)
    return CONFIGURED_TOKEN


@pytest.fixture
def unconfigured_key(monkeypatch):
    """No key configured -- what `os.environ.get(..., "")` leaves behind."""
    monkeypatch.setattr(mcp_server, "_MCP_API_KEY", "")


# --- The verifier, with a key configured -----------------------------------

# Token shapes, not just the obvious two. A rejection suite closed on the shapes
# that came to mind is how a bypass survives: every one of these returns None,
# but they reach that answer through different branches, and the non-ASCII case
# did not reach it at all before this file existed.

REJECTED_TOKENS = [
    pytest.param("wrong-token", id="wrong-ascii-value"),
    pytest.param("", id="empty-string"),
    pytest.param(CONFIGURED_TOKEN + "x", id="correct-key-with-suffix"),
    pytest.param(CONFIGURED_TOKEN[:-1], id="correct-key-truncated"),
    pytest.param("tokén", id="non-ascii"),
    pytest.param("tok\x00en", id="embedded-null-byte"),
    pytest.param("A" * 100_000, id="very-long"),
]


def test_a_correctly_configured_token_is_accepted(configured_key):
    """
    The non-vacuity anchor for every rejection case below.

    A verifier that refuses everything satisfies all of them and none of it
    would show, so this is the assertion the rest of the file leans on.
    """
    granted = verify(configured_key)

    assert granted is not None
    assert granted.token == configured_key
    assert granted.client_id == "auro_mcp_client"
    assert granted.scopes == ["all"]


@pytest.mark.parametrize("token", REJECTED_TOKENS)
def test_a_token_that_is_not_the_configured_one_is_refused(configured_key, token):
    """Refused by returning None, and without raising -- see the next test."""
    assert verify(token) is None


@pytest.mark.parametrize("token", REJECTED_TOKENS)
def test_refusing_a_token_never_raises(configured_key, token):
    """
    Returning None and raising are not the same refusal.

    `secrets.compare_digest` rejects non-ASCII str operands with TypeError, so a
    token carrying any byte above 0x7f used to leave the verifier by exception
    rather than by decision. Nothing admitted the caller, but the verifier had
    stopped deciding, and an auth surface that crashes on attacker-chosen input
    is not one that refuses it.
    """
    try:
        verify(token)
    except Exception as exc:  # noqa: BLE001 -- the point is that none escape
        pytest.fail(f"verifier raised {type(exc).__name__} instead of refusing: {exc}")


# --- The verifier, with no key configured ----------------------------------


@pytest.mark.parametrize(
    "token", [CONFIGURED_TOKEN, "", "anything", "tokén"], ids=["real-key", "empty", "any", "non-ascii"]
)
def test_an_unconfigured_key_refuses_rather_than_admits(unconfigured_key, token):
    """
    Valence, stated because the same empty value could defensibly mean either.

    An unset credential means *refuse every caller*, never *authentication is
    not required*. The empty key is the state the process starts in before
    AURO_MCP_API_KEY is read, and the fail-open reading of it would admit the
    whole internet.
    """
    assert verify(token) is None


# --- The transport, where the header is actually parsed --------------------


def test_a_correct_bearer_header_admits_the_caller(configured_key):
    """The transport-level non-vacuity anchor, for the same reason as above."""
    result = authenticate(f"Bearer {configured_key}")

    assert result is not None
    credentials, user = result
    assert "all" in credentials.scopes
    assert user.access_token.client_id == "auro_mcp_client"


@pytest.mark.parametrize(
    "header",
    [
        pytest.param(None, id="absent-header"),
        pytest.param("", id="empty-header"),
        pytest.param(CONFIGURED_TOKEN, id="bare-token-no-scheme"),
        pytest.param(f"Basic {CONFIGURED_TOKEN}", id="wrong-scheme"),
        pytest.param("Bearer", id="scheme-only"),
        pytest.param("Bearer ", id="scheme-with-empty-token"),
        pytest.param("Bearer wrong-token", id="wrong-token"),
        pytest.param("Bearer tokén", id="non-ascii-token"),
    ],
)
def test_a_header_that_does_not_carry_the_configured_token_is_refused(
    configured_key, header
):
    """
    Covers the close condition's "malformed or absent Authorization header",
    which is decided one layer above the verifier: BearerAuthBackend returns
    None for an absent or non-Bearer header without ever calling verify_token.
    """
    assert authenticate(header) is None


def test_an_unconfigured_key_refuses_a_well_formed_bearer_header(unconfigured_key):
    """Fail-closed survives the layer above: a valid-looking header still fails."""
    assert authenticate(f"Bearer {CONFIGURED_TOKEN}") is None


# --- Startup: the key the comparison assumes -------------------------------


def _run_mcp_cli(repo_root, tmp_path, api_key: str):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    env = os.environ.copy()
    env["AURO_WORKSPACE_ROOT"] = str(workspace)
    env["AURO_MCP_API_KEY"] = api_key
    return subprocess.run(
        [
            sys.executable, "-B", "-m", "auro_runtime", "mcp",
            "--transport", "streamable-http",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )


def test_a_non_ascii_api_key_is_refused_at_startup(repo_root, tmp_path):
    """
    The header and the environment are decoded by two different parsers.

    Starlette decodes the Authorization header as latin-1; the environment is
    decoded by the OS. Comparing them means comparing the output of two parsers
    that agree only on ASCII -- so a non-ASCII key configures a listener whose
    auth can never match any token, which reviews as a working control and is an
    empty one. Refusing the key at startup is what keeps the two in a range where
    they cannot disagree.
    """
    proc = _run_mcp_cli(repo_root, tmp_path, "kéy-with-non-ascii")

    assert proc.returncode == 1
    assert "AURO_MCP_API_KEY" in proc.stderr
    assert "ASCII" in proc.stderr


def test_an_absent_api_key_is_refused_at_startup(repo_root, tmp_path):
    """The pre-existing guard, pinned here beside the one added next to it."""
    proc = _run_mcp_cli(repo_root, tmp_path, "")

    assert proc.returncode == 1
    assert "AURO_MCP_API_KEY must be set" in proc.stderr
