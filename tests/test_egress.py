"""Destination control for outbound HTTP.

`auro_runtime.egress` validates inside urllib3's `_new_conn()`, below the URL
parser and below redirect handling: it resolves the name there, refuses if any
returned address is denied, and dials a vetted literal. These tests hold that
contract at the boundary — host forms, deny-set membership, schemes, proxies.

Every case runs against loopback or a stubbed resolver. Nothing leaves the
machine.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from auro_runtime import egress
from auro_runtime.egress import address_is_denied
from runtime_tools.http_request_tools import http_request


@pytest.fixture
def server():
    """Loopback HTTP server. Yields (port, served_paths)."""
    served: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            served.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"INTERNAL-ONLY")

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.server_address[1], served
    finally:
        httpd.shutdown()


# ---------------------------------------------------------------------------
# Host forms
# ---------------------------------------------------------------------------

# requests decodes percent-encoding in prepare_url, after both urlparse and
# urllib3.util.parse_url have reported the host. The string handed to a
# pre-flight check is therefore not the string requests dials, which is why the
# check runs at connect time against the resolved address instead.
PERCENT_ENCODED = [
    "%31%32%37%2e%30%2e%30%2e%31",
    "%6c%6f%63%61%6c%68%6f%73%74",
    "127%2e0%2e0%2e1",
]


@pytest.mark.parametrize("host", PERCENT_ENCODED)
def test_percent_encoded_hosts_are_refused(server, host):
    port, served = server

    result = http_request(url=f"http://{host}:{port}/x")

    assert "Blocked request" in result["error"], result
    assert served == []


@pytest.mark.parametrize("host", ["localhost.", "LOCALHOST.", "LoCaLhOsT"])
def test_trailing_dot_and_case_variants_are_refused(server, host):
    """A trailing-dot FQDN is the same name to the resolver, not to a regex."""
    port, served = server

    result = http_request(url=f"http://{host}:{port}/x")

    assert "Blocked request" in result["error"], result
    assert served == []


# ---------------------------------------------------------------------------
# Numeric host forms
# ---------------------------------------------------------------------------

# glibc routes numeric-looking names through __nss_hostname_digits_dots, which
# uses inet_aton semantics and accepts all of these. Windows returns NXDOMAIN,
# so on Windows the OS answers before the guard is consulted, and an OS default
# refusing something is not coverage on either platform. These run against a
# resolver stubbed to answer the way glibc does, so the guard is what refuses
# them on the platform where they resolve.
GLIBC_NUMERIC = {
    "2130706433": "127.0.0.1",
    "0177.0.0.1": "127.0.0.1",
    "0x7f000001": "127.0.0.1",
    "0x7f.0.0.1": "127.0.0.1",
    "127.1": "127.0.0.1",
    "127.0.1": "127.0.0.1",
    "0": "0.0.0.0",
}


@pytest.fixture
def glibc_resolver(monkeypatch):
    """Answer numeric host forms the way glibc does, not the way Windows does."""
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        if host in GLIBC_NUMERIC:
            addr = GLIBC_NUMERIC[host]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.mark.parametrize("host", sorted(GLIBC_NUMERIC))
def test_numeric_host_forms_are_refused_by_the_guard(server, glibc_resolver, host):
    port, served = server

    result = http_request(url=f"http://{host}:{port}/x")

    assert "Blocked request" in result["error"], (
        f"{host} was not refused by the guard: {result}. If this failed with a "
        "connection error instead, the resolver stub is not in effect and the "
        "test is measuring Windows' NXDOMAIN rather than the guard."
    )
    assert served == []


# ---------------------------------------------------------------------------
# Deny-set membership
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "address, why",
    [
        ("127.0.0.1", "loopback"),
        ("10.0.0.1", "RFC1918"),
        ("172.16.0.1", "RFC1918"),
        ("192.168.1.1", "RFC1918"),
        ("169.254.169.254", "link-local"),
        ("0.0.0.0", "unspecified"),
        ("0.0.0.1", "0.0.0.0/8, non-canonical"),
        ("100.64.0.1", "shared address space, missed by all six category properties"),
        ("192.88.99.1", "6to4 relay anycast, which is_global reports as global"),
        ("::1", "IPv6 loopback"),
        ("fd00::1", "IPv6 unique-local"),
        ("fe80::1", "IPv6 link-local"),
        ("::", "IPv6 unspecified"),
        ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
        ("::ffff:169.254.169.254", "IPv4-mapped link-local"),
        ("::127.0.0.1", "deprecated IPv4-compatible form"),
        ("2002:7f00:1::", "6to4 carrying 127.0.0.1"),
        ("64:ff9b::7f00:1", "NAT64 carrying 127.0.0.1"),
    ],
)
def test_address_is_denied(address, why):
    assert address_is_denied(ipaddress.ip_address(address)) is not None, why


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", "1.1.1.1", "140.82.121.4", "93.184.216.34",
     "2606:4700::1111", "2a00:1450:4001:80e::200e", "::ffff:8.8.8.8"],
)
def test_globally_routable_addresses_are_permitted(address):
    """Negative control. Every refusal case above would also pass if the
    deny-set simply returned a reason for everything."""
    assert address_is_denied(ipaddress.ip_address(address)) is None


@pytest.mark.parametrize(
    "address, why",
    [
        ("2002:7f00:1::", "6to4 carrying 127.0.0.1"),
        ("2001::1", "Teredo, tunnels over IPv4"),
        ("100.64.0.1", "shared address space"),
        ("192.88.99.1", "6to4 relay anycast"),
        ("64:ff9b::7f00:1", "NAT64 carrying 127.0.0.1"),
        ("::127.0.0.1", "deprecated IPv4-compatible form"),
        ("192.0.0.1", "IETF protocol assignments"),
        ("198.18.0.1", "benchmarking range"),
        ("240.0.0.1", "reserved for future use"),
        ("3ffe::1", "6bone, deprecated"),
    ],
)
def test_special_purpose_ranges_are_denied_without_consulting_properties(address, why):
    """These must be denied by explicit membership, not by a category property.

    `ipaddress`'s notion of which ranges are private changes between patch
    releases: CPython gh-113171 added 2002::/16 to the IPv6 private networks in
    3.11.10 / 3.12.4, and on 3.11.9 `2002:7f00:1::` reports is_private False and
    is_global True.

    Asserting membership rather than the verdict is what makes this test
    interpreter-independent: it fails identically on 3.10.11 and on 3.13 if a
    range is dropped, where `address_is_denied(...) is not None` would quietly
    pass on whichever interpreters happened to classify it for us.
    """
    from auro_runtime.egress import _EXTRA_DENIED, _effective_address

    addr = _effective_address(ipaddress.ip_address(address))
    assert any(
        addr.version == net.version and addr in net for net in _EXTRA_DENIED
    ), (
        f"{address} ({why}) is not covered by an explicit range and is therefore "
        "trusting the interpreter's ipaddress module to classify it"
    )


def test_ipv4_mapped_addresses_are_collapsed_explicitly():
    """The category properties must not be trusted to do this themselves.

    IPv6Address.is_loopback only delegates through ipv4_mapped on CPython
    >= 3.11.10 / 3.12.5. This project supports 3.10 (requires-python, and CI
    runs it), where ip_address("::ffff:127.0.0.1").is_loopback is False. The
    deny-set collapses the mapping itself so the verdict is identical on every
    supported interpreter -- a classifier whose answer depends on the
    interpreter version has the same defect as one that depends on the host OS.
    """
    mapped = ipaddress.ip_address("::ffff:127.0.0.1")
    assert egress._effective_address(mapped) == ipaddress.ip_address("127.0.0.1")
    assert address_is_denied(mapped) is not None

    public = ipaddress.ip_address("::ffff:8.8.8.8")
    assert egress._effective_address(public) == ipaddress.ip_address("8.8.8.8")
    assert address_is_denied(public) is None


def test_a_name_resolving_to_both_public_and_private_is_refused(server, monkeypatch):
    """Any denied address in the answer refuses the whole request.

    Falling back to the permitted sibling would connect successfully and leave
    the caller believing the name is safe.
    """
    port, served = server
    real = socket.getaddrinfo

    def split_horizon(host, prt, *args, **kwargs):
        if host == "rebind.example":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", prt)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", prt)),
            ]
        return real(host, prt, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", split_horizon)

    result = http_request(url=f"http://rebind.example:{port}/x")

    assert "127.0.0.1 is a loopback address" in result["error"]
    assert served == []


# ---------------------------------------------------------------------------
# Scheme and proxy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "file:///C:/Windows/win.ini",
    "ftp://example.invalid/x",
    "gopher://example.invalid/x",
    "data:text/plain,hello",
])
def test_non_http_schemes_are_refused(url):
    assert "Unsupported scheme" in http_request(url=url)["error"]


def test_a_configured_proxy_refuses_rather_than_validating_the_proxy(monkeypatch):
    """With a proxy the destination never reaches the connection check.

    The connection is made to the proxy and the real destination travels inside
    CONNECT or an absolute-form URI, so the check would validate the proxy and
    report a guarantee it did not make. D-038: refuse instead.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:8080")

    result = http_request(url="http://example.invalid/x")

    assert "proxy is configured" in result["error"]
