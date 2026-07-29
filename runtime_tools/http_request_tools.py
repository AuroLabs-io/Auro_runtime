"""
Generic HTTP request tool. Supports GET and POST to external APIs.

Destination filtering is best-effort and **string-level only**. `_is_blocked_url`
inspects the URL text once, before the request is issued, and never learns where
the connection actually goes. It does not resolve hostnames, does not revalidate
redirect hops, and covers no IPv6 ranges. It is not an SSRF control and must not
be relied on to prevent access to internal services. See
OT-http-request-destination-is-unenforced.
"""

import ipaddress
import re
from urllib.parse import urlparse

from auro_runtime.executor import register
from auro_runtime.tool_schemas import HttpRequestArgs

_BLOCKED_HOSTS = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|\[::1\])$", re.IGNORECASE
)

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_blocked_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except Exception:
        return "Invalid URL."
    host = parsed.hostname or ""
    if not host:
        return "No host in URL."
    if _BLOCKED_HOSTS.match(host):
        return "Requests to localhost/loopback are blocked."
    try:
        addr = ipaddress.ip_address(host)
        for net in _PRIVATE_RANGES:
            if addr in net:
                return "Requests to private/internal IP ranges are blocked."
    except ValueError:
        pass
    if parsed.scheme not in ("http", "https"):
        return f"Unsupported scheme: {parsed.scheme}. Use http or https."
    return None


_AUTH_SCHEMES = {"bearer": "Bearer", "basic": "Basic", "token": "Token"}


@register(
    "http_request",
    "Make an HTTP GET or POST request to an external URL. Returns status, headers, and body. "
    "Authenticate with auth_alias rather than a raw token. "
    "Rejects URLs whose host is written as a literal loopback or IPv4 private-range "
    "address. This is a string check only: it does not resolve hostnames, does not "
    "re-check redirect targets, and does not cover IPv6. Treat any destination as "
    "potentially internal and do not use this tool to reach a URL you were told is "
    "safe on the basis of that check.",
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
    blocked = _is_blocked_url(url)
    if blocked:
        return {"error": blocked}

    method = method.upper()
    if method not in ("GET", "POST"):
        return {"error": f"Unsupported method: {method}. Use GET or POST."}

    if auth_alias:
        scheme = _AUTH_SCHEMES.get((auth_scheme or "Bearer").strip().lower())
        if scheme is None:
            return {"error": f"Unsupported auth_scheme: {auth_scheme}. Use Bearer, Basic, or Token."}
        from auro_runtime.secrets import get_secret

        token = get_secret(auth_alias)
        if not token:
            # Name the alias, never the value.
            return {"error": f"Credential alias '{auth_alias}' is not configured."}
        headers = dict(headers or {})
        headers["Authorization"] = f"{scheme} {token}"

    try:
        import requests
    except ImportError:
        return {"error": "requests library not installed."}

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=timeout)
        else:
            r = requests.post(url, headers=headers, data=body, timeout=timeout)

        response_body = r.text[:10000]
        return {
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body": response_body,
            "truncated": len(r.text) > 10000,
        }
    except requests.exceptions.Timeout:
        return {"error": f"Request timed out after {timeout}s."}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"Connection failed: {e}"}
    except Exception as e:
        return {"error": str(e)}
