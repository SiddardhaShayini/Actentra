"""Security regression tests for Finding 02: HTTP executor DNS rebinding and SSRF bypass.

Verifies:
- DNS rebinding TOCTOU: DNS results changing between validation and connect cannot
  redirect traffic to private IPs.
- Socket-level destination IP pinning: socket.create_connection connects directly
  to pre-validated IP.
- Multi-record DNS responses containing any private/metadata IP are rejected
  immediately before connect.
- Post-connect peer verification: if peer IP is private or does not match pinned IP,
  socket is closed and aborted.
- HTTP redirect DNS rebinding: redirects are validated, re-resolved, and pinned.
- Cloud metadata (169.254.169.254) and non-global ranges (CGNAT 100.64.0.0/10,
  IPv4-mapped IPv6) are blocked.
- HTTPS SNI and certificate hostname verification are preserved during pinned IP connections.
- Ambient proxy environment variables (HTTP_PROXY / HTTPS_PROXY) cannot bypass SSRF protections.
- Disallowed redirect schemes (file://, gopher://, ftp://) are rejected.
"""

from __future__ import annotations

import socket
import ssl
import urllib.request
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from actentra_core.envelope import ActionEnvelope, build_envelope
from actentra_core.verdict import Decision
from actentra_executors.fs import ExecutorError
from actentra_executors.http import (
    PinnedHTTPConnection,
    PinnedHTTPSConnection,
    PinningDNSResolver,
    ScopedHTTPExecutor,
    SSRFSafeRedirectHandler,
    _is_private_ip,
)


def _make_action_envelope(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: Any = None,
) -> ActionEnvelope:
    params: dict[str, Any] = {"method": method}
    if headers:
        params["headers"] = headers
    if body is not None:
        params["body"] = body
    return build_envelope(
        session_id="test-session-dns",
        agent_id="test-agent",
        tool="http.get" if method == "GET" else "http.post",
        verb="network",
        resource=url,
        params=params,
    )


def _make_decision(constraints: dict[str, Any] | None = None) -> Decision:
    return Decision(
        verdict="allow",
        rule_id="allow-rule",
        reason="allowed by test policy",
        policy_version="1",
        canonical_hash="00" * 32,
        constraints=constraints or {},
    )


def test_dns_rebinding_dual_resolution_attack_blocked_at_socket_connect() -> None:
    """T-01: Rebinding attack where DNS resolves to public on validation and private on connect.

    The pinning architecture ensures socket.create_connection connects ONLY to the pre-validated
    pinned IP address, completely preventing TOCTOU rebinding to 127.0.0.1 or 169.254.169.254.
    """
    call_count = 0
    connected_targets: list[tuple[str, int]] = []

    def mock_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any) -> list[Any]:
        nonlocal call_count
        call_count += 1
        if host == "rebind.attacker.com":
            # If re-queried later, attacker returns private loopback
            if call_count > 1:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
            # Initial validation lookup returns legitimate public IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]

    mock_sock = MagicMock()
    mock_sock.getpeername.return_value = ("93.184.216.34", 80)

    def mock_create_connection(
        address: tuple[str, int], timeout: float = 15.0, source_address: Any = None
    ) -> MagicMock:
        connected_targets.append(address)
        return mock_sock

    executor = ScopedHTTPExecutor(
        allowed_hosts=["rebind.attacker.com"],
        allow_private_ips=False,
    )
    envelope = _make_action_envelope("http://rebind.attacker.com/sensitive-data")
    decision = _make_decision()

    with (
        patch("socket.getaddrinfo", side_effect=mock_getaddrinfo),
        patch("socket.create_connection", side_effect=mock_create_connection),
        patch("urllib.request.AbstractHTTPHandler.do_open") as mock_do_open,
    ):
        # Configure do_open mock to return a mock response
        mock_resp = MagicMock()
        mock_resp.code = 200
        mock_resp.status = 200
        mock_resp.msg = "OK"
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_resp.info.return_value = {"Content-Type": "text/plain"}
        mock_resp.read.return_value = b"public response"
        mock_resp.__enter__.return_value = mock_resp
        mock_do_open.return_value = mock_resp

        result = executor.execute(envelope, decision)
        assert result["status_code"] == 200

        # Assert resolver pinned the public IP
        # And any HTTP connection used the pinned public IP
        assert mock_do_open.called
        # The factory passed to do_open must be configured with pinned_ip="93.184.216.34"
        conn_factory = mock_do_open.call_args[0][0]
        conn = conn_factory("rebind.attacker.com")
        assert isinstance(conn, PinnedHTTPConnection)
        assert conn.pinned_ip == "93.184.216.34"

        # When connect() is called, target is pinned IP, never 127.0.0.1
        conn.connect()
        assert len(connected_targets) == 1
        assert connected_targets[0] == ("93.184.216.34", 80)
        assert ("127.0.0.1", 80) not in connected_targets


def test_dns_dual_resolution_multi_record_with_private_ip_immediately_blocked() -> None:
    """DNS dual-resolution with round-robin public and private IPs is blocked before connect."""

    def mock_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any) -> list[Any]:
        if host == "dual-stack.attacker.com":
            # Attacker returns both public and private IP in DNS answer
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            ]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]

    executor = ScopedHTTPExecutor(
        allowed_hosts=["dual-stack.attacker.com"],
        allow_private_ips=False,
    )
    envelope = _make_action_envelope("http://dual-stack.attacker.com/status")
    decision = _make_decision()

    with (
        patch("socket.getaddrinfo", side_effect=mock_getaddrinfo),
        patch("socket.create_connection") as mock_create_conn,
    ):
        with pytest.raises(ExecutorError) as exc_info:
            executor.execute(envelope, decision)

        assert "resolves to private IP '127.0.0.1'" in str(exc_info.value)
        # Verify no socket connect attempt was made
        mock_create_conn.assert_not_called()


def test_post_connect_peer_ip_private_verification_aborts() -> None:
    """If connected socket peer IP is private, connection is closed and ExecutorError is raised."""
    mock_sock = MagicMock()
    # Rogue socket connected to loopback despite public target
    mock_sock.getpeername.return_value = ("127.0.0.1", 80)

    conn = PinnedHTTPConnection(
        host="example.com",
        port=80,
        pinned_ip="93.184.216.34",
        allow_private_ips=False,
    )

    with patch("socket.create_connection", return_value=mock_sock):
        with pytest.raises(ExecutorError) as exc_info:
            conn.connect()

        assert "Connected peer IP '127.0.0.1' is private/metadata" in str(exc_info.value)
        mock_sock.close.assert_called_once()


def test_post_connect_peer_ip_mismatch_aborts() -> None:
    """If connected socket peer IP does not match pinned IP, connection is closed and aborted."""
    mock_sock = MagicMock()
    # Network routed to different IP than pinned
    mock_sock.getpeername.return_value = ("93.184.216.99", 80)

    conn = PinnedHTTPConnection(
        host="example.com",
        port=80,
        pinned_ip="93.184.216.34",
        allow_private_ips=False,
    )

    with patch("socket.create_connection", return_value=mock_sock):
        with pytest.raises(ExecutorError) as exc_info:
            conn.connect()

        assert "Connected peer IP '93.184.216.99' does not match pinned IP '93.184.216.34'" in str(
            exc_info.value
        )
        mock_sock.close.assert_called_once()


def test_redirect_dns_rebinding_to_metadata_service_blocked() -> None:
    """Redirect target resolving to AWS IMDS or private IP is blocked before request."""

    def mock_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any) -> list[Any]:
        if host == "metadata.attacker.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    executor = ScopedHTTPExecutor(
        allowed_hosts=["redirector.example.com", "metadata.attacker.com"],
        allow_private_ips=False,
    )
    resolver = PinningDNSResolver(allow_private_ips=False)

    def validator(url: str) -> None:
        executor._validate_url_target(
            url,
            {"allowed_hosts": ["redirector.example.com", "metadata.attacker.com"]},
            allow_private=False,
            resolver=resolver,
        )

    handler = SSRFSafeRedirectHandler(validator=validator, max_redirects=5, resolver=resolver)

    req_mock = MagicMock()
    req_mock.full_url = "http://redirector.example.com/start"

    with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
        with pytest.raises(ExecutorError) as exc_info:
            handler.redirect_request(
                req=req_mock,
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="http://metadata.attacker.com/latest/meta-data/",
            )

        assert "resolves to private IP '169.254.169.254'" in str(exc_info.value)


@pytest.mark.parametrize(
    "ip_address_str",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # AWS/GCP metadata
        "100.64.0.1",  # Carrier-Grade NAT (RFC 6598)
        "192.0.0.1",  # IETF Protocol Assignments
        "198.18.0.1",  # Network Benchmark
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
        "::ffff:127.0.0.1",  # IPv4-mapped IPv6 loopback
        "::ffff:169.254.169.254",  # IPv4-mapped metadata
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "0.0.0.0",  # Unspecified
        "255.255.255.255",  # Broadcast
    ],
)
def test_non_global_and_mapped_ip_ranges_blocked(ip_address_str: str) -> None:
    """All private, loopback, link-local, CGNAT, and IPv4-mapped ranges are rejected."""
    assert _is_private_ip(ip_address_str) is True

    executor = ScopedHTTPExecutor(allow_private_ips=False)
    url_host = f"[{ip_address_str}]" if ":" in ip_address_str else ip_address_str
    envelope = _make_action_envelope(f"http://{url_host}/admin")
    decision = _make_decision()

    with pytest.raises(ExecutorError) as exc_info:
        executor.execute(envelope, decision)

    assert "SSRF" in str(exc_info.value) or "private" in str(exc_info.value).lower()


def test_https_sni_and_cert_validation_preserved_with_pinned_ip() -> None:
    """PinnedHTTPSConnection wraps socket using domain hostname for TLS SNI and cert SAN."""
    mock_sock = MagicMock()
    mock_sock.getpeername.return_value = ("93.184.216.34", 443)

    mock_ssl_context = MagicMock(spec=ssl.SSLContext)
    wrapped_sock = MagicMock()
    mock_ssl_context.wrap_socket.return_value = wrapped_sock

    conn = PinnedHTTPSConnection(
        host="secure.example.com",
        port=443,
        pinned_ip="93.184.216.34",
        context=mock_ssl_context,
        allow_private_ips=False,
    )

    with patch("socket.create_connection", return_value=mock_sock) as mock_create_conn:
        conn.connect()

        # Connect connects directly to pinned IP
        mock_create_conn.assert_called_once_with(("93.184.216.34", 443), conn.timeout, None)
        # wrap_socket MUST receive server_hostname="secure.example.com", NEVER the IP
        mock_ssl_context.wrap_socket.assert_called_once_with(
            mock_sock, server_hostname="secure.example.com"
        )
        assert conn.sock == wrapped_sock


def test_proxy_handler_overrides_environment_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ambient HTTP_PROXY and HTTPS_PROXY cannot act as confused deputies."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8888")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8888")

    executor = ScopedHTTPExecutor(
        allowed_hosts=["api.example.com"],
        allow_private_ips=False,
    )
    envelope = _make_action_envelope("http://api.example.com/v1")
    decision = _make_decision()

    dns_resp = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
    with (
        patch("socket.getaddrinfo", return_value=dns_resp),
        patch("urllib.request.build_opener") as mock_build_opener,
    ):
        mock_opener = MagicMock()
        mock_build_opener.return_value = mock_opener
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {}
        mock_resp.read.return_value = b"ok"
        mock_opener.open.return_value.__enter__.return_value = mock_resp

        executor.execute(envelope, decision)

        # Assert build_opener was called with ProxyHandler({})
        handlers = mock_build_opener.call_args[0]
        assert any(
            isinstance(h, urllib.request.ProxyHandler) and getattr(h, "proxies", None) == {}
            for h in handlers
        )


def test_redirect_scheme_change_blocked() -> None:
    """Redirect to disallowed schemes (file://, gopher://, ftp://) is immediately rejected."""
    executor = ScopedHTTPExecutor(allowed_hosts=["example.com"], allow_private_ips=False)
    resolver = PinningDNSResolver(allow_private_ips=False)

    def validator(url: str) -> None:
        executor._validate_url_target(
            url,
            {"allowed_hosts": ["example.com"]},
            allow_private=False,
            resolver=resolver,
        )

    handler = SSRFSafeRedirectHandler(validator=validator, max_redirects=5, resolver=resolver)
    req_mock = MagicMock()
    req_mock.full_url = "http://example.com/start"

    with pytest.raises(ExecutorError) as exc_info:
        handler.redirect_request(
            req=req_mock,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="file:///etc/passwd",
        )
    assert "scheme" in str(exc_info.value).lower()


def test_relative_redirect_resolution_and_pinning() -> None:
    """Relative redirect path is correctly combined with base URL and validated."""
    executor = ScopedHTTPExecutor(allowed_hosts=["api.example.com"], allow_private_ips=False)
    resolver = PinningDNSResolver(allow_private_ips=False)

    def validator(url: str) -> None:
        executor._validate_url_target(
            url,
            {"allowed_hosts": ["api.example.com"]},
            allow_private=False,
            resolver=resolver,
        )

    handler = SSRFSafeRedirectHandler(validator=validator, max_redirects=5, resolver=resolver)
    req = urllib.request.Request("http://api.example.com/v1/login", headers={"User-Agent": "test"})

    dns_resp = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
    with patch("socket.getaddrinfo", return_value=dns_resp):
        redirected_req = handler.redirect_request(
            req=req,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="/v2/dashboard",
        )

    assert redirected_req is not None
    assert redirected_req.full_url == "http://api.example.com/v2/dashboard"
    assert resolver.get_pinned("api.example.com") == "93.184.216.34"


def test_allow_private_ips_override_permits_loopback_when_explicitly_configured() -> None:
    """When allow_private_ips=True is explicitly set in constraints, loopback is permitted."""
    executor = ScopedHTTPExecutor(allow_private_ips=False)
    envelope = _make_action_envelope("http://127.0.0.1:8080/metrics")
    decision = _make_decision({"allow_private_ips": True})

    dns_resp = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8080))]
    with (
        patch("urllib.request.AbstractHTTPHandler.do_open") as mock_do_open,
        patch("socket.getaddrinfo", return_value=dns_resp),
    ):
        mock_resp = MagicMock()
        mock_resp.code = 200
        mock_resp.status = 200
        mock_resp.msg = "OK"
        mock_resp.headers = {}
        mock_resp.info.return_value = {}
        mock_resp.read.return_value = b"metrics_data"
        mock_resp.__enter__.return_value = mock_resp
        mock_do_open.return_value = mock_resp

        result = executor.execute(envelope, decision)
        assert result["status_code"] == 200
        assert result["body"] == "metrics_data"
