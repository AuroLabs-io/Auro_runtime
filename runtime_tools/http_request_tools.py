"""
Generic HTTP request tool. Supports GET and POST to external APIs.

Destination control lives in `auro_runtime.egress`, not here. This module used
to carry its own `_is_blocked_url()`, which inspected the URL text once before
the request and never learned where the connection actually went -- a hostname
resolving inward passed it, a redirect walked past it, IPv6 was absent, and two
separate parser defects let a crafted string reach loopback outright. Replaced
2026-08-17 by a check that runs at connect time against the resolved address.

A tool must not carry its own destination check. The kernel owns that boundary
so that a weaker per-tool substitute cannot exist; see
OT-http-request-destination-is-unenforced.
"""

import requests

from auro_runtime.egress import BlockedDestinationError, guarded_request
from auro_runtime.executor import register
from auro_runtime.tool_schemas import HttpRequestArgs

_AUTH_SCHEMES = {"bearer": "Bearer", "basic": "Basic", "token": "Token"}


@register(
    "http_request",
    "Make an HTTP GET or POST request to an external URL. Returns status, headers, and body. "
    "Authenticate with auth_alias rather than a raw token. "
    "The destination is checked at connection time against the resolved IP address, on the "
    "initial request and again on every redirect hop. Loopback, private, link-local, reserved, "
    "and any address that is not globally routable are refused, on both IPv4 and IPv6. "
    "Requests are refused outright when an HTTP proxy is configured, because the check cannot "
    "see the real destination through one. http and https only.",
    args_schema=HttpRequestArgs,
)
def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 30,
    auth_alias: str | None = None,
    auth_scheme: str = "Bearer",
) -> dict:
    """
    Make an HTTP request. Returns status code, response headers, and body text.

    auth_alias is resolved here, at call time, and injected into the outbound
    Authorization header. The secret is never returned in the result, so it
    cannot reach model context or the audit trail.
    """
    # Only for a clearer message than InvalidSchema. The control is the mount
    # table in `guarded_session()`, which has no adapter for anything else.
    scheme = (url.split(":", 1)[0] if ":" in url else "").lower()
    if scheme not in ("http", "https"):
        return {"error": f"Unsupported scheme: {scheme}. Use http or https."}

    method = method.upper()
    if method not in ("GET", "POST"):
        return {"error": f"Unsupported method: {method}. Use GET or POST."}

    if auth_alias:
        auth = _AUTH_SCHEMES.get((auth_scheme or "Bearer").strip().lower())
        if auth is None:
            return {"error": f"Unsupported auth_scheme: {auth_scheme}. Use Bearer, Basic, or Token."}
        from auro_runtime.secrets import get_secret

        token = get_secret(auth_alias)
        if not token:
            # Name the alias, never the value.
            return {"error": f"Credential alias '{auth_alias}' is not configured."}
        headers = dict(headers or {})
        headers["Authorization"] = f"{auth} {token}"

    try:
        r = guarded_request(
            method,
            url,
            headers=headers,
            data=body if method == "POST" else None,
            timeout=timeout,
        )

        response_body = r.text[:10000]
        return {
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body": response_body,
            "truncated": len(r.text) > 10000,
        }
    except BlockedDestinationError as e:
        return {"error": str(e)}
    except requests.exceptions.Timeout:
        return {"error": f"Request timed out after {timeout}s."}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"Connection failed: {e}"}
    except Exception as e:
        return {"error": str(e)}
