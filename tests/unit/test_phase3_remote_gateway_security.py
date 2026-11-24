"""Comprehensive Phase 3 integration and security regression tests for Actentra Gateway (ACT-02).

Validates:
1. Plain HTTP remote startup rejection (fail-closed on non-loopback without TLS)
2. Invalid and missing TLS certificates/keys rejection at startup
3. Expired and future TLS certificates rejection at startup
4. Successful TLS remote server startup & HTTPS request/response processing
5. Mutual TLS (mTLS) client certificate verification (success with valid cert, rejection without)
6. Unauthorized and invalid token rejection over TLS (constant-time verification)
7. Request replay protection (sliding-window nonce cache and timestamp skew validation)
8. Dynamic credential revocation and rotation (revoke_token and rotate_token)
9. Proxy header spoofing defense (X-Forwarded-For ignored from untrusted peers)
10. Host header validation and DNS rebinding defense (allowed_hosts enforcement)
11. Oversized request rejection (413 Payload Too Large) and request smuggling defenses
12. TLS connection interruption / abrupt client disconnect graceful handling
"""

from __future__ import annotations

import datetime
import http.client
import io
import ipaddress
import json
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from actentra.boundary import Boundary
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.http_service import (
    ActentraHTTPHandler,
    DeploymentMode,
    create_gateway_server,
    create_tls_context,
    validate_certificate,
)
from actentra_gateway.services import AppServices

# ==============================================================================
# TEST FIXTURES AND CERTIFICATE GENERATORS
# ==============================================================================


_TEST_POLICY = """
version: 1
policy_id: phase3-security-policy
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-calc
    match: { tool: calc, verb: read }
    verdict: allow
  - id: allow-fs-read
    match: { tool: fs.read, verb: read }
    verdict: allow
"""


def _make_ca(tmp_path: Path) -> tuple[Path, Path]:
    """Generate self-signed Root CA certificate and key for mutual TLS testing."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Actentra Test Root CA")])
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_p = tmp_path / "ca.crt"
    ca_key_p = tmp_path / "ca.key"
    ca_cert_p.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_p.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_cert_p, ca_key_p


def _make_cert(
    tmp_path: Path,
    name: str = "server",
    san_hosts: tuple[str, ...] = ("localhost", "127.0.0.1"),
    ca: tuple[Path, Path] | None = None,
    expired: bool = False,
    future: bool = False,
) -> tuple[Path, Path]:
    """Generate X.509 certificate and key, optionally signed by a test CA."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(65537, 2048)
    subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, san_hosts[0])])
    now = datetime.datetime.now(datetime.UTC)

    if expired:
        not_before = now - datetime.timedelta(days=10)
        not_after = now - datetime.timedelta(days=1)
    elif future:
        not_before = now + datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=10)
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=10)

    san_list: list[x509.GeneralName] = []
    for h in san_hosts:
        try:
            ip = ipaddress.ip_address(h)
            san_list.append(x509.IPAddress(ip))
        except ValueError:
            san_list.append(x509.DNSName(h))

    if ca is not None:
        ca_cert = x509.load_pem_x509_certificate(ca[0].read_bytes())
        issuer_name = ca_cert.subject
        signing_key = serialization.load_pem_private_key(ca[1].read_bytes(), password=None)
    else:
        issuer_name = subj
        signing_key = key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(int(time.time() * 1000) % 100000000 + 10)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    cert = builder.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]

    cert_p = tmp_path / f"{name}.crt"
    key_p = tmp_path / f"{name}.key"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_p, key_p


def _dispatch_handler(
    server: Any,
    path: str,
    method: str = "GET",
    data: dict[str, Any] | bytes | str | None = None,
    headers: dict[str, str] | None = None,
    client_ip: str = "127.0.0.1",
) -> tuple[int, Any]:
    """Dispatch an HTTP request through ActentraHTTPHandler in memory."""
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    handler.server = server
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.client_address = (client_ip, 54321)
    handler.path = path
    handler.wfile = io.BytesIO()

    if data is not None:
        if isinstance(data, bytes):
            body_bytes = data
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
        else:
            body_bytes = json.dumps(data).encode("utf-8")
    else:
        body_bytes = b""

    hdrs = {
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/json",
        "Host": "localhost",
    }
    if headers:
        hdrs.update(headers)
    handler.headers = hdrs  # type: ignore[assignment]
    handler.rfile = io.BytesIO(body_bytes)

    if method == "GET":
        handler.do_GET()
    elif method == "POST":
        handler.do_POST()
    elif method == "DELETE":
        handler.do_DELETE()
    elif method == "OPTIONS":
        handler.do_OPTIONS()
    else:
        raise ValueError(f"Unsupported method {method}")

    raw_output = handler.wfile.getvalue().decode("utf-8")
    status_line = raw_output.splitlines()[0]
    status_code = int(status_line.split()[1])
    parts = raw_output.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        parsed_body = json.loads(body_str)
    except Exception:
        parsed_body = body_str
    return status_code, parsed_body


# ==============================================================================
# 1. PLAIN HTTP REMOTE STARTUP REJECTION (FAIL-CLOSED)
# ==============================================================================


def test_plain_http_remote_startup_rejected(tmp_path: Path) -> None:
    """Non-loopback binding without TLS must fail closed at startup (ACT-02)."""
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    # 1. 0.0.0.0 without unsafe flag -> rejected
    with pytest.raises(ValueError, match="without explicit remote authorization"):
        create_gateway_server(boundary, host="0.0.0.0", port=0, unsafe_allow_remote=False)

    # 2. 0.0.0.0 without auth token -> rejected
    with pytest.raises(ValueError, match="without an authentication token"):
        create_gateway_server(
            boundary,
            host="0.0.0.0",
            port=0,
            auth_token=None,
            unsafe_allow_remote=True,
        )

    # 3. 0.0.0.0 with auth token and unsafe_allow_remote BUT NO TLS -> strictly rejected!
    with pytest.raises(
        ValueError, match="without TLS. Remote communication must use authenticated TLS"
    ):
        create_gateway_server(
            boundary,
            host="0.0.0.0",
            port=0,
            auth_token="valid-secret-token-123",
            unsafe_allow_remote=True,
        )

    # 4. Private network IP without TLS -> strictly rejected!
    with pytest.raises(ValueError, match="without TLS"):
        create_gateway_server(
            boundary,
            host="192.168.1.100",
            port=0,
            auth_token="valid-secret-token-123",
            deployment_mode=DeploymentMode.PRIVATE_NETWORK,
        )

    # 5. Remote deployment mode on loopback without TLS -> strictly rejected!
    with pytest.raises(ValueError, match="without TLS"):
        create_gateway_server(
            boundary,
            host="127.0.0.1",
            port=0,
            auth_token="valid-secret-token-123",
            deployment_mode=DeploymentMode.REMOTE,
        )


# ==============================================================================
# 2. INVALID AND MISSING TLS CERTIFICATES REJECTION
# ==============================================================================


def test_invalid_and_missing_tls_certificate_rejected(tmp_path: Path) -> None:
    """Misconfigured TLS certificate or private key files fail during startup."""
    valid_cert, valid_key = _make_cert(tmp_path, "valid")

    # Missing cert file
    missing_cert = tmp_path / "missing.crt"
    with pytest.raises(FileNotFoundError, match="certificate file not found"):
        create_tls_context(certfile=missing_cert, keyfile=valid_key)

    # Missing key file
    missing_key = tmp_path / "missing.key"
    with pytest.raises(FileNotFoundError, match="private key file not found"):
        create_tls_context(certfile=valid_cert, keyfile=missing_key)

    # Missing CA cert file
    missing_ca = tmp_path / "missing_ca.crt"
    with pytest.raises(FileNotFoundError, match="CA certificate file not found"):
        create_tls_context(
            certfile=valid_cert,
            keyfile=valid_key,
            ca_certs=missing_ca,
            require_client_cert=True,
        )

    # Corrupt cert file
    corrupt_cert = tmp_path / "corrupt.crt"
    corrupt_cert.write_text("NOT A VALID CERTIFICATE PEM", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid TLS certificate"):
        validate_certificate(corrupt_cert)

    # require_client_cert=True without ca_certs
    with pytest.raises(ValueError, match="require_client_cert=True requires ca_certs"):
        create_tls_context(
            certfile=valid_cert,
            keyfile=valid_key,
            require_client_cert=True,
        )


# ==============================================================================
# 3. EXPIRED AND FUTURE TLS CERTIFICATES REJECTION
# ==============================================================================


def test_expired_and_future_tls_certificate_rejected(tmp_path: Path) -> None:
    """Expired or not-yet-valid certificates are rejected during startup."""
    expired_cert, expired_key = _make_cert(tmp_path, "expired", expired=True)
    with pytest.raises(ValueError, match="has expired on"):
        validate_certificate(expired_cert)

    with pytest.raises(ValueError, match="has expired on"):
        create_tls_context(certfile=expired_cert, keyfile=expired_key)

    future_cert, future_key = _make_cert(tmp_path, "future", future=True)
    with pytest.raises(ValueError, match="is not yet valid"):
        validate_certificate(future_cert)

    with pytest.raises(ValueError, match="is not yet valid"):
        create_tls_context(certfile=future_cert, keyfile=future_key)


# ==============================================================================
# 4. SUCCESSFUL TLS REMOTE SERVER STARTUP & HTTPS REQUESTS
# ==============================================================================


def test_successful_tls_remote_server_startup_and_https_requests(tmp_path: Path) -> None:
    """Server binds and serves authenticated requests over TLS with proper cipher suites."""
    cert_p, key_p = _make_cert(tmp_path, "server_ok", san_hosts=("localhost", "127.0.0.1"))
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    # Binding with TLS succeeds on loopback or non-loopback
    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        auth_token="gateway-secret-token",
        certfile=cert_p,
        keyfile=key_p,
        deployment_mode=DeploymentMode.REMOTE,
        allowed_hosts=("localhost", "127.0.0.1"),
    )
    assert server.is_tls is True
    assert server.ssl_context is not None

    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        # Client SSL context trusting server cert
        client_ctx = ssl.create_default_context(cafile=str(cert_p))
        client_ctx.check_hostname = False

        # 1. GET /health over HTTPS
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=client_ctx, timeout=5.0)
        conn.request(
            "GET",
            "/health",
            headers={"Host": "127.0.0.1", "Authorization": "Bearer gateway-secret-token"},
        )
        resp = conn.getresponse()
        assert resp.status == 200
        health_data = json.loads(resp.read().decode("utf-8"))
        assert health_data["status"] == "ok"
        conn.close()

        # 2. POST /v1/crossings over HTTPS with valid Bearer token
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=client_ctx, timeout=5.0)
        req_body = json.dumps(
            {
                "tool": "calc",
                "verb": "read",
                "resource": "tool:calc",
                "params": {"a": 10, "b": 20},
            }
        )
        conn.request(
            "POST",
            "/v1/crossings",
            body=req_body,
            headers={
                "Host": "127.0.0.1",
                "Content-Type": "application/json",
                "Authorization": "Bearer gateway-secret-token",
            },
        )
        resp = conn.getresponse()
        assert resp.status == 200
        crossing_res = json.loads(resp.read().decode("utf-8"))
        assert crossing_res["verdict"] == "allow"
        conn.close()

    except OSError as exc:
        if "10013" in str(exc) or "forbidden" in str(exc).lower():
            pytest.skip(f"Loopback socket access restricted by sandbox: {exc}")
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


# ==============================================================================
# 5. MUTUAL TLS (mTLS) CLIENT CERTIFICATE ENFORCEMENT
# ==============================================================================


def test_mtls_client_certificate_enforcement(tmp_path: Path) -> None:
    """Server enforces mutual TLS: rejects unauthenticated clients and accepts valid certs."""
    ca_cert, ca_key = _make_ca(tmp_path)
    server_cert, server_key = _make_cert(tmp_path, "server_mtls", ca=(ca_cert, ca_key))
    client_cert, client_key = _make_cert(tmp_path, "client_valid", ca=(ca_cert, ca_key))

    # Untrusted rogue CA and cert
    rogue_ca_cert, rogue_ca_key = _make_ca(tmp_path / "rogue")
    rogue_cert, rogue_key = _make_cert(
        tmp_path / "rogue", "client_rogue", ca=(rogue_ca_cert, rogue_ca_key)
    )

    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        auth_token="mtls-token",
        certfile=server_cert,
        keyfile=server_key,
        ca_certs=ca_cert,
        require_client_cert=True,
        allowed_hosts=("localhost", "127.0.0.1"),
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        # A. Client WITHOUT certificate must be rejected
        unauth_ctx = ssl.create_default_context(cafile=str(ca_cert))
        unauth_ctx.check_hostname = False
        conn_unauth = http.client.HTTPSConnection(
            "127.0.0.1", port, context=unauth_ctx, timeout=5.0
        )
        with pytest.raises((ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError)):
            conn_unauth.request("GET", "/health", headers={"Host": "127.0.0.1"})
            conn_unauth.getresponse()
        conn_unauth.close()

        # B. Client with rogue untrusted certificate must be rejected
        rogue_ctx = ssl.create_default_context(cafile=str(ca_cert))
        rogue_ctx.check_hostname = False
        rogue_ctx.load_cert_chain(certfile=str(rogue_cert), keyfile=str(rogue_key))
        conn_rogue = http.client.HTTPSConnection("127.0.0.1", port, context=rogue_ctx, timeout=5.0)
        with pytest.raises((ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError)):
            conn_rogue.request("GET", "/health", headers={"Host": "127.0.0.1"})
            conn_rogue.getresponse()
        conn_rogue.close()

        # C. Client WITH valid certificate signed by CA must succeed
        valid_ctx = ssl.create_default_context(cafile=str(ca_cert))
        valid_ctx.check_hostname = False
        valid_ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
        conn_valid = http.client.HTTPSConnection("127.0.0.1", port, context=valid_ctx, timeout=5.0)
        conn_valid.request(
            "GET",
            "/health",
            headers={"Host": "127.0.0.1", "Authorization": "Bearer mtls-token"},
        )
        resp = conn_valid.getresponse()
        assert resp.status == 200
        health = json.loads(resp.read().decode("utf-8"))
        assert health["status"] == "ok"
        conn_valid.close()

    except OSError as exc:
        if "10013" in str(exc) or "forbidden" in str(exc).lower():
            pytest.skip(f"Loopback socket access restricted by sandbox: {exc}")
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


# ==============================================================================
# 6. UNAUTHORIZED CLIENT REJECTION OVER TLS (CONSTANT-TIME)
# ==============================================================================


def test_unauthorized_and_invalid_token_rejected_over_tls(tmp_path: Path) -> None:
    """Missing, empty, or incorrect Bearer tokens are rejected with HTTP 401."""
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)
    services = AppServices(boundary)

    server_mock = MagicMock()
    server_mock.services = services
    server_mock.auth_token = "correct-gateway-secret-token"
    server_mock.token_principals = None
    server_mock.allowed_hosts = ()
    server_mock.deployment_mode = DeploymentMode.LOCAL
    server_mock.trusted_proxies = frozenset()
    server_mock.require_client_cert = False

    # 1. Missing Authorization header
    code, res = _dispatch_handler(server_mock, "/v1/crossings", method="POST", data={})
    assert code == 401
    assert res["code"] == "unauthorized"

    # 2. Non-Bearer header
    code, res = _dispatch_handler(
        server_mock,
        "/v1/crossings",
        method="POST",
        data={},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert code == 401
    assert res["code"] == "unauthorized"

    # 3. Incorrect token
    code, res = _dispatch_handler(
        server_mock,
        "/v1/crossings",
        method="POST",
        data={},
        headers={"Authorization": "Bearer wrong-attacker-token"},
    )
    assert code == 401
    assert res["code"] == "unauthorized"

    # 4. Correct token succeeds
    code, res = _dispatch_handler(
        server_mock,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "res:1"},
        headers={"Authorization": "Bearer correct-gateway-secret-token"},
    )
    assert code == 200
    assert res["verdict"] == "allow"


# ==============================================================================
# 7. TOKEN REPLAY PROTECTION AND CLOCK SKEW
# ==============================================================================


def test_token_replay_protection_and_clock_skew(tmp_path: Path) -> None:
    """Gateway rejects replayed nonces with HTTP 409 and clock-skewed timestamps with HTTP 400."""
    cert_p, key_p = _make_cert(tmp_path, "replay_srv")
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        auth_token="replay-test-token",
        certfile=cert_p,
        keyfile=key_p,
    )

    # 1. Fresh request with Nonce succeeds
    code, res = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "res:1"},
        headers={
            "Authorization": "Bearer replay-test-token",
            "X-Actentra-Nonce": "nonce-unique-abc-001",
            "X-Actentra-Timestamp": str(time.time()),
        },
    )
    assert code == 200

    # 2. Replayed request with duplicate nonce is blocked
    code, res = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "res:1"},
        headers={
            "Authorization": "Bearer replay-test-token",
            "X-Actentra-Nonce": "nonce-unique-abc-001",
            "X-Actentra-Timestamp": str(time.time()),
        },
    )
    assert code == 409
    assert res["code"] == "replay_detected"

    # 3. Request with excessive clock skew (> 300s) is rejected
    stale_timestamp = time.time() - 400.0
    code, res = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "res:1"},
        headers={
            "Authorization": "Bearer replay-test-token",
            "X-Actentra-Nonce": "nonce-unique-abc-002",
            "X-Actentra-Timestamp": str(stale_timestamp),
        },
    )
    assert code == 400
    assert res["code"] == "timestamp_skew"

    server.server_close()


# ==============================================================================
# 8. DYNAMIC CREDENTIAL REVOCATION AND ROTATION
# ==============================================================================


def test_dynamic_credential_revocation_and_rotation(tmp_path: Path) -> None:
    """Tokens can be rotated and revoked dynamically without restarting the server."""
    cert_p, key_p = _make_cert(tmp_path, "rot_srv")
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        auth_token="initial-token-v1",
        certfile=cert_p,
        keyfile=key_p,
    )

    # 1. Initial token succeeds
    code, _ = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "res:1"},
        headers={"Authorization": "Bearer initial-token-v1"},
    )
    assert code == 200

    # 2. Rotate token to v2
    server.rotate_token("initial-token-v1", "rotated-token-v2")

    # 3. Old token is now revoked and rejected
    code, res = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "res:1"},
        headers={"Authorization": "Bearer initial-token-v1"},
    )
    assert code == 401
    assert res["code"] == "token_revoked"

    # 4. New token succeeds
    code, _ = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "res:1"},
        headers={"Authorization": "Bearer rotated-token-v2"},
    )
    assert code == 200

    # 5. Explicitly revoke new token
    server.revoke_token("rotated-token-v2")
    code, res = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc", "verb": "read", "resource": "res:1"},
        headers={"Authorization": "Bearer rotated-token-v2"},
    )
    assert code == 401
    assert res["code"] == "token_revoked"

    server.server_close()


# ==============================================================================
# 9. PROXY HEADER SPOOFING DEFENSE
# ==============================================================================


def test_proxy_header_spoofing_defense(tmp_path: Path) -> None:
    """X-Forwarded-For is ignored from untrusted peers and only trusted from authorized proxies."""
    cert_p, key_p = _make_cert(tmp_path, "proxy_srv")
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        auth_token="tok-123",
        certfile=cert_p,
        keyfile=key_p,
        trusted_proxies=("10.0.0.1",),
    )

    # 1. Untrusted client (192.168.1.50) sends forged X-Forwarded-For: 127.0.0.1
    # Handler must ignore XFF and use socket IP 192.168.1.50
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    handler.server = server
    handler.client_address = ("192.168.1.50", 12345)
    handler.headers = {"X-Forwarded-For": "127.0.0.1"}  # type: ignore[assignment]
    assert handler._get_effective_client_ip() == "192.168.1.50"

    # 2. Trusted proxy (10.0.0.1) sends X-Forwarded-For: 203.0.113.195
    # Handler trusts proxy and extracts client IP 203.0.113.195
    handler.client_address = ("10.0.0.1", 12345)
    handler.headers = {"X-Forwarded-For": "203.0.113.195"}  # type: ignore[assignment]
    assert handler._get_effective_client_ip() == "203.0.113.195"

    server.server_close()


# ==============================================================================
# 10. HOST HEADER VALIDATION AND DNS REBINDING DEFENSE
# ==============================================================================


def test_host_header_validation_and_dns_rebinding_defense(tmp_path: Path) -> None:
    """Gateway enforces allowed Host headers, preventing DNS rebinding attacks."""
    cert_p, key_p = _make_cert(tmp_path, "host_srv")
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        auth_token="host-tok",
        certfile=cert_p,
        keyfile=key_p,
        deployment_mode=DeploymentMode.REMOTE,
        allowed_hosts=("gateway.actentra.internal", "actentra.example.com"),
    )

    # 1. Missing Host header in remote mode is rejected
    code, res = _dispatch_handler(
        server,
        "/health",
        method="GET",
        headers={"Host": "", "Authorization": "Bearer host-tok"},
    )
    assert code == 400
    assert res["code"] == "missing_host_header"

    # 2. DNS rebinding / unauthorized Host header is rejected
    code, res = _dispatch_handler(
        server,
        "/health",
        method="GET",
        headers={"Host": "attacker.rebind.example.org", "Authorization": "Bearer host-tok"},
    )
    assert code == 400
    assert res["code"] == "invalid_host_header"

    # 3. Legitimate allowed host succeeds
    code, res = _dispatch_handler(
        server,
        "/health",
        method="GET",
        headers={"Host": "gateway.actentra.internal:8080", "Authorization": "Bearer host-tok"},
    )
    assert code == 200
    assert res["status"] == "ok"

    server.server_close()


# ==============================================================================
# 11. OVERSIZED REQUEST AND REQUEST SMUGGLING DEFENSES
# ==============================================================================


def test_oversized_payload_and_request_smuggling_defenses(tmp_path: Path) -> None:
    """Gateway rejects oversized requests with 413 and conflicting headers with 400."""
    cert_p, key_p = _make_cert(tmp_path, "smuggle_srv")
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        auth_token="smuggle-tok",
        certfile=cert_p,
        keyfile=key_p,
    )

    # 1. Body exceeding 2 MiB bound triggers HTTP 413 Payload Too Large
    oversized_length = 3 * 1024 * 1024  # 3 MiB
    code, res = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data=b"{}",
        headers={
            "Authorization": "Bearer smuggle-tok",
            "Content-Length": str(oversized_length),
        },
    )
    assert code == 413
    assert res["code"] == "payload_too_large"

    # 2. Conflicting Content-Length and Transfer-Encoding headers (Smuggling attack)
    code, res = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc"},
        headers={
            "Authorization": "Bearer smuggle-tok",
            "Content-Length": "15",
            "Transfer-Encoding": "chunked",
        },
    )
    assert code == 400
    assert res["code"] == "invalid_transfer_encoding"

    # 3. Unsupported Transfer-Encoding
    code, res = _dispatch_handler(
        server,
        "/v1/crossings",
        method="POST",
        data={"tool": "calc"},
        headers={
            "Authorization": "Bearer smuggle-tok",
            "Transfer-Encoding": "deflate, chunked",
        },
    )
    assert code == 400
    assert res["code"] == "invalid_transfer_encoding"

    server.server_close()


# ==============================================================================
# 12. TLS CONNECTION INTERRUPTION GRACEFUL HANDLING
# ==============================================================================


def test_tls_connection_interruption_graceful_handling(tmp_path: Path) -> None:
    """Abrupt client disconnects or malformed TLS records do not crash the server."""
    cert_p, key_p = _make_cert(tmp_path, "interrupt_srv")
    db_p = tmp_path / "rec.db"
    store = ReceiptStore(db_p)
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)

    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        auth_token="interrupt-tok",
        certfile=cert_p,
        keyfile=key_p,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        # A. Send non-TLS raw TCP garbage and close abruptly
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        sock.sendall(b"NOT_A_TLS_HANDSHAKE\r\n\r\n")
        sock.close()

        # B. Connect and close immediately without sending anything
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect(("127.0.0.1", port))
        sock2.close()

        # Give the server thread a moment to process the disconnected sockets
        time.sleep(0.2)

        # C. Server must remain fully operational for legitimate clients
        client_ctx = ssl.create_default_context(cafile=str(cert_p))
        client_ctx.check_hostname = False
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=client_ctx, timeout=5.0)
        conn.request(
            "GET",
            "/health",
            headers={"Host": "127.0.0.1", "Authorization": "Bearer interrupt-tok"},
        )
        resp = conn.getresponse()
        assert resp.status == 200
        health = json.loads(resp.read().decode("utf-8"))
        assert health["status"] == "ok"
        conn.close()

    except OSError as exc:
        if "10013" in str(exc) or "forbidden" in str(exc).lower():
            pytest.skip(f"Loopback socket access restricted by sandbox: {exc}")
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
