r"""
Destination control for outbound HTTP.

Every network-capable tool routes through `guarded_request()`. The check runs
inside the connection layer -- urllib3's `_new_conn()`, below the URL parser
and below requests' redirect handling -- because no check on the URL *string*
can be sound. That is not a preference. Three string-level bypasses were
verified against this runtime, and the third rules the approach out entirely:

    http://127.0.0.1:8080\@legit-looking-host.example/
        `urlparse` reads the host as `legit-looking-host.example` (RFC 3986,
        `@` delimits userinfo); urllib3 terminates the authority at the
        backslash, WHATWG-style, and dials 127.0.0.1. The two parsers
        disagree, so validating with either one validates the wrong host.

    http://internal.example.com/
        Resolves wherever DNS points. A name is not an address, so no amount
        of string analysis constrains the destination.

    http://%6c%6f%63%61%6c%68%6f%73%74/
        BOTH parsers report the host as the percent-encoded literal, and both
        are wrong: requests decodes it afterwards, in `prepare_url` ->
        `unquote_unreserved`, and dials `localhost`. The string a guard is
        handed is not the string requests sends. Verified 2026-08-17.

The third case is why "normalize and re-parse" was rejected rather than kept
as a weaker fallback: there is no normalized form to check, because the
mutation happens after any check a caller could perform. Law 10 -- validation
and action must agree on what the input means -- has one satisfying answer
here, which is to validate where the action happens.

What this module checks is therefore the *resolved address*, at connect time,
for every connection the session opens. Redirects need no special handling: a
redirect opens a new connection, and every connection comes through here.

See OT-http-request-destination-is-unenforced.
"""

import ipaddress
import socket
from socket import timeout as SocketTimeout
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.util import connection as urllib3_connection


class BlockedDestinationError(Exception):
    """
    Raised when a destination is refused.

    Deliberately not an OSError subclass. requests wraps OSError as
    ConnectionError and urllib3 retries several OSError shapes, either of
    which would turn a refusal into a generic connection failure and lose the
    reason. This propagates out of `Session.request` intact.
    """


# Ranges denied by explicit membership rather than by `is_global` or the
# category properties, because those verdicts move with the interpreter.
#
# CPython gh-113171 added `2002::/16` to the IPv6 private networks in 3.11.10 /
# 3.12.4 / 3.13. On 3.11.9 `2002:7f00:1::` reports is_private False and
# is_global True, so it was ALLOWED -- a 6to4 address embedding 127.0.0.1.
# Caught by CI 2026-08-17 on windows-3.11 and windows-3.10, and only there:
# 3.11.9 and 3.10.11 are the final Windows binary releases of those branches,
# so those runners are frozen before the fix while the Linux runners track
# current patches. The suite passed locally on 3.11.14 and on all four ubuntu
# jobs, which is precisely how a version-dependent hole stays invisible.
#
# This is the same reasoning as `_effective_address` and it should have been
# applied here at the same time: a classifier whose answer depends on the
# interpreter is the same defect as one whose answer depends on the host OS.
# Anything tunnelling, embedding, or otherwise special-purpose is listed --
# not left to a property whose membership CPython may revise. The category
# properties and `is_global` still run, as belt and braces, over the top.
_EXTRA_DENIED = (
    ipaddress.ip_network("100.64.0.0/10"),   # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),    # IETF protocol assignments
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 relay anycast
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking
    ipaddress.ip_network("240.0.0.0/4"),     # reserved for future use
    ipaddress.ip_network("::/96"),           # IPv4-compatible IPv6 (deprecated)
    ipaddress.ip_network("64:ff9b::/96"),    # NAT64 well-known prefix
    ipaddress.ip_network("64:ff9b:1::/48"),  # NAT64 local-use prefix
    ipaddress.ip_network("2001::/32"),       # Teredo -- tunnels over IPv4
    ipaddress.ip_network("2002::/16"),       # 6to4 -- embeds an IPv4 address
    ipaddress.ip_network("3ffe::/16"),       # 6bone, deprecated
    ipaddress.ip_network("5f00::/8"),        # deprecated
)

# Most specific first. Several addresses satisfy more than one of these --
# fe80::1 is link-local and private, 169.254.169.254 likewise -- and the
# narrower category is the more useful thing to tell an operator. Order
# affects only which reason is reported, never whether the address is refused.
_CATEGORY_PROPERTIES = (
    ("is_loopback", "a loopback address"),
    ("is_link_local", "a link-local address"),
    ("is_private", "a private address"),
    ("is_reserved", "a reserved address"),
    ("is_multicast", "a multicast address"),
    ("is_unspecified", "an unspecified address"),
)


def _effective_address(addr):
    """
    Collapse an IPv4-mapped IPv6 address to the IPv4 address it carries.

    `IPv6Address.is_loopback` and its siblings only delegate through
    `ipv4_mapped` on CPython >= 3.11.10 / 3.12.5. This project supports 3.10
    (see requires-python, and CI runs it), where
    `ip_address("::ffff:127.0.0.1").is_loopback` is False -- so the category
    properties alone would pass an address that reaches IPv4 loopback on any
    dual-stack host. Collapsing explicitly makes the verdict identical on
    every supported interpreter, which is the whole point: a classifier whose
    answer depends on the interpreter version is the same defect as one whose
    answer depends on the host OS.
    """
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def address_is_denied(addr) -> str | None:
    """
    Return a refusal reason for `addr`, or None if it may be contacted.

    Fail-closed and inverted per D-038: an address is refused unless it is
    affirmatively globally routable. Enumerating bad ranges was the previous
    approach and the set is unbounded -- the old `_PRIVATE_RANGES` held five
    IPv4 networks and missed carrier-grade NAT, every IPv6 range, and both
    IPv4-in-IPv6 embeddings.

    `is_global` alone is not sufficient in the other direction: it reports
    True for 6to4 relay anycast, NAT64 and IPv4-compatible IPv6. Those are
    subtracted explicitly. The six category properties are checked as well,
    so an interpreter whose `is_global` regresses still fails closed instead
    of silently opening.
    """
    addr = _effective_address(addr)
    # Categories first, so the reason an operator reads is the specific one:
    # `::1` is reported as loopback rather than as a member of `::/96`, which
    # it also is. Order affects only the message, never the verdict.
    for prop, description in _CATEGORY_PROPERTIES:
        if getattr(addr, prop, False):
            return f"{addr} is {description}"
    for net in _EXTRA_DENIED:
        if addr.version == net.version and addr in net:
            return f"{addr} is within {net}, which is not a permitted destination"
    if not addr.is_global:
        return f"{addr} is not a globally routable address"
    return None


def _guarded_new_conn(conn):
    r"""
    Resolve, validate every resulting address, then dial a vetted one.

    Replaces `HTTPConnection._new_conn`. `conn.host` and `conn._dns_host` are
    deliberately left untouched: `host` is a property over `_dns_host`, and
    TLS SNI, certificate hostname verification and the outbound Host header
    all read it. Pinning by rewriting the host would break three things at
    once. Resolution happens here instead and `create_connection` is handed a
    literal address, which also closes the DNS-rebinding window -- the address
    that was validated is the address that gets dialled, with no second
    lookup in between.

    If ANY address the name resolves to is denied, the request is refused
    rather than falling back to a permitted sibling. A name answering with
    both a public and a private address is the rebinding shape itself, and
    quietly picking the safe one leaves the caller believing the name is safe.
    """
    host = conn._dns_host.strip("[]")
    port = conn.port

    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise NameResolutionError(conn.host, conn, e) from e

    if not infos:
        raise BlockedDestinationError(
            f"Blocked request to {host}: the name resolved to no addresses."
        )

    for *_unused, sockaddr in infos:
        literal = sockaddr[0].split("%", 1)[0]  # drop any IPv6 scope id
        try:
            addr = ipaddress.ip_address(literal)
        except ValueError as e:
            raise BlockedDestinationError(
                f"Blocked request to {host}: resolved to {sockaddr[0]!r}, "
                "which is not an IP address."
            ) from e
        reason = address_is_denied(addr)
        if reason:
            raise BlockedDestinationError(f"Blocked request to {host}: {reason}.")

    last_error = None
    for *_unused, sockaddr in infos:
        try:
            return urllib3_connection.create_connection(
                (sockaddr[0], port),
                conn.timeout,
                source_address=conn.source_address,
                socket_options=conn.socket_options,
            )
        except SocketTimeout as e:
            raise ConnectTimeoutError(
                conn,
                f"Connection to {conn.host} timed out. (connect timeout={conn.timeout})",
            ) from e
        except OSError as e:
            last_error = e
    raise NewConnectionError(conn, f"Failed to establish a new connection: {last_error}")


class _GuardedHTTPConnection(HTTPConnection):
    def _new_conn(self):
        return _guarded_new_conn(self)


class _GuardedHTTPSConnection(HTTPSConnection):
    def _new_conn(self):
        return _guarded_new_conn(self)


class _GuardedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class GuardedAdapter(HTTPAdapter):
    """Transport adapter whose pools build destination-checked connections."""

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        # Replace the mapping, never mutate it. PoolManager.__init__ assigns
        # the module-global `pool_classes_by_scheme` by reference with no
        # copy -- unlike `key_fn_by_scheme` on the following line, which does
        # copy. Mutating in place would swap the connection class for every
        # PoolManager in the process, including the model backend's, which
        # legitimately must reach loopback for a local Ollama server.
        self.poolmanager.pool_classes_by_scheme = {
            "http": _GuardedHTTPConnectionPool,
            "https": _GuardedHTTPSConnectionPool,
        }


def _configured_proxy(url: str) -> str | None:
    """Return the proxy that would carry `url`, or None. Honours no_proxy."""
    try:
        proxies = requests.utils.get_environ_proxies(url)
    except Exception:
        return None
    scheme = urlparse(url).scheme
    return proxies.get(scheme) or proxies.get("all")


def guarded_session() -> requests.Session:
    """
    A session whose every http/https connection is destination-checked.

    Mounted on http and https only. Any other scheme -- file://, ftp://,
    gopher:// -- has no adapter and raises InvalidSchema, including when
    reached as a redirect target. That was previously true only because no
    transport adapter for those schemes happened to be installed, which the
    egress sweep correctly called a dependency accident rather than a
    control. Here it is the mount table, which is a control.
    """
    session = requests.Session()
    adapter = GuardedAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def guarded_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: str | None = None,
    timeout: int = 30,
) -> requests.Response:
    """
    Issue a destination-checked HTTP request.

    Raises BlockedDestinationError if the destination is refused, on the
    initial URL or on any redirect hop.
    """
    proxy = _configured_proxy(url)
    if proxy is not None:
        raise BlockedDestinationError(
            "Refusing: a proxy is configured for this destination. With a proxy "
            "the connection is made to the proxy and the real destination "
            "travels inside CONNECT or an absolute-form URI, so this check "
            "would validate the proxy rather than the target. Refusing beats "
            "reporting a guarantee it cannot provide."
        )
    session = guarded_session()
    try:
        return session.request(method, url, headers=headers, data=data, timeout=timeout)
    finally:
        session.close()
