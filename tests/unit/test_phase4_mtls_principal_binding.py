"""Tests for Phase 4 mTLS transport-to-application principal binding."""

from __future__ import annotations

import datetime
import hashlib
import http.client
import io
import json
import ssl
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from actentra.boundary import Boundary
from actentra_core.identity import (
    CertificatePrincipalBinding,
    IdentitySecurityError,
    MTLSPrincipalRegistry,
    extract_certificate_identity,
    resolve_http_caller_context,
)
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.http_service import (
    ActentraHTTPHandler,
    DeploymentMode,
    create_gateway_server,
)
from actentra_gateway.services import AppServices

_TEST_POLICY = """
version: 1
policy_id: test-mtls-binding
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-read
    match: { verb: read }
    verdict: allow
"""


def _make_ca_and_cert(
    out_dir: Path,
    cn: str,
    *,
    san_uri: str | None = None,
    ca: tuple[x509.Certificate, rsa.RSAPrivateKey] | None = None,
    days_offset_start: int = -1,
    days_offset_end: int = 30,
) -> tuple[Path, Path, bytes, x509.Certificate, rsa.RSAPrivateKey]:
    out_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    if ca is None:
        issuer = subject
        sign_key = key
        is_ca = True
    else:
        issuer = ca[0].subject
        sign_key = ca[1]
        is_ca = False

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=days_offset_start))
        .not_valid_after(now + datetime.timedelta(days=days_offset_end))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    san_entries: list[x509.GeneralName] = [x509.DNSName("127.0.0.1"), x509.DNSName("localhost")]
    if san_uri:
        san_entries.append(x509.UniformResourceIdentifier(san_uri))
    builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    cert = builder.sign(sign_key, hashes.SHA256())
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    cert_p = out_dir / f"{cn}.crt"
    key_p = out_dir / f"{cn}.key"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_p, key_p, der_bytes, cert, key


def _fp(der_bytes: bytes) -> str:
    return f"sha256:{hashlib.sha256(der_bytes).hexdigest().lower()}"


def _dispatch_with_cert(
    server_mock: Any,
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    peer_der: bytes | None = None,
    is_tls: bool = True,
) -> tuple[int, Any]:
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    handler.server = server_mock
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.path = path
    handler.wfile = io.BytesIO()
    handler.rfile = io.BytesIO(b"")
    handler.client_address = ("10.0.0.5", 54321)

    if is_tls:
        ssl_sock = MagicMock(spec=ssl.SSLSocket)
        ssl_sock.getpeercert.return_value = peer_der
        handler.connection = ssl_sock
    else:
        handler.connection = MagicMock()

    hdrs = {"Host": "gateway.actentra.internal", "Content-Length": "0"}
    if headers:
        hdrs.update(headers)
    handler.headers = hdrs  # type: ignore[assignment]

    if method == "GET":
        handler.do_GET()
    else:
        handler.do_POST()

    raw_output = handler.wfile.getvalue().decode("utf-8")
    status_code = int(raw_output.splitlines()[0].split()[1])
    parts = raw_output.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        parsed_body = json.loads(body_str)
    except Exception:
        parsed_body = body_str
    return status_code, parsed_body


def test_mtls_valid_and_mismatched_token_and_unknown_cert(tmp_path: Path) -> None:
    """Valid cert+matching token succeeds; mismatched token or unknown cert fails closed."""
    _, _, _, ca_cert, ca_key = _make_ca_and_cert(tmp_path / "ca", "TestCA")
    _, _, alice_der, _, _ = _make_ca_and_cert(
        tmp_path / "alice", "alice", san_uri="spiffe://actentra/agents/alice", ca=(ca_cert, ca_key)
    )
    _, _, bob_der, _, _ = _make_ca_and_cert(
        tmp_path / "bob", "bob", san_uri="spiffe://actentra/agents/bob", ca=(ca_cert, ca_key)
    )
    _, _, unknown_der, _, _ = _make_ca_and_cert(
        tmp_path / "unk",
        "unknown",
        san_uri="spiffe://actentra/agents/unknown",
        ca=(ca_cert, ca_key),
    )

    cert_reg = MTLSPrincipalRegistry.from_dict(
        {
            "agent-alice": {
                "fingerprints": [_fp(alice_der)],
                "san_uris": ["spiffe://actentra/agents/alice"],
                "scopes": ["crossings:read", "receipts:read"],
                "allowed_agents": ["agent-alice"],
            },
            "agent-bob": {
                "fingerprints": [_fp(bob_der)],
                "san_uris": ["spiffe://actentra/agents/bob"],
                "scopes": ["crossings:read", "receipts:read", "crossings:execute"],
                "allowed_agents": ["agent-bob"],
            },
        }
    )
    token_principals = {
        "tok-alice": {"principal_id": "agent-alice", "scopes": ["crossings:read", "receipts:read"]},
        "tok-bob": {"principal_id": "agent-bob", "scopes": ["crossings:read", "receipts:read"]},
    }

    store = ReceiptStore(tmp_path / "r.db")
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)
    server_mock = MagicMock()
    server_mock.services = AppServices(boundary)
    server_mock.auth_token = None
    server_mock.token_principals = token_principals
    server_mock.cert_registry = cert_reg
    server_mock.require_client_cert = True
    server_mock.deployment_mode = DeploymentMode.REMOTE
    server_mock.allowed_hosts = ("gateway.actentra.internal",)
    server_mock.trusted_proxies = frozenset()

    # 1. Valid Alice cert + Alice token -> 200 OK
    code, _ = _dispatch_with_cert(
        server_mock,
        "/v1/receipts",
        headers={"Authorization": "Bearer tok-alice"},
        peer_der=alice_der,
    )
    assert code == 200

    # 2. Alice cert + Bob token (identity mismatch!) -> 403 Forbidden
    code_mis, res_mis = _dispatch_with_cert(
        server_mock,
        "/v1/receipts",
        headers={"Authorization": "Bearer tok-bob"},
        peer_der=alice_der,
    )
    assert code_mis == 403
    assert res_mis["code"] == "mtls_identity_mismatch"
    assert "mismatch" in res_mis["error"].lower()

    # 3. Unknown CA-signed cert + Alice token -> 403 Forbidden
    code_unk, res_unk = _dispatch_with_cert(
        server_mock,
        "/v1/receipts",
        headers={"Authorization": "Bearer tok-alice"},
        peer_der=unknown_der,
    )
    assert code_unk == 403
    assert res_unk["code"] == "mtls_principal_rejected"

    # 4. Missing client certificate -> 403 Forbidden
    code_no_cert, res_no_cert = _dispatch_with_cert(
        server_mock,
        "/v1/receipts",
        headers={"Authorization": "Bearer tok-alice"},
        peer_der=None,
    )
    assert code_no_cert == 403
    assert res_no_cert["code"] == "mtls_certificate_required"


def test_mtls_expired_revoked_issuer_and_ambiguous_mappings(tmp_path: Path) -> None:
    """Expired cert, revoked cert, wrong issuer, and ambiguous mappings are rejected."""
    _, _, _, ca_cert, ca_key = _make_ca_and_cert(tmp_path / "ca1", "TrustedCA")
    _, _, _, other_ca_cert, other_ca_key = _make_ca_and_cert(tmp_path / "ca2", "OtherCA")

    _, _, valid_der, _, _ = _make_ca_and_cert(tmp_path / "v", "v", ca=(ca_cert, ca_key))
    _, _, expired_der, _, _ = _make_ca_and_cert(
        tmp_path / "exp",
        "exp",
        ca=(ca_cert, ca_key),
        days_offset_start=-10,
        days_offset_end=-1,
    )
    _, _, wrong_iss_der, _, _ = _make_ca_and_cert(
        tmp_path / "wi", "wi", ca=(other_ca_cert, other_ca_key)
    )

    reg = MTLSPrincipalRegistry()
    reg.register_binding(
        CertificatePrincipalBinding(
            principal_id="svc-1",
            fingerprints=(_fp(valid_der), _fp(expired_der), _fp(wrong_iss_der)),
            allowed_issuers=("TrustedCA",),
        )
    )

    # Ambiguous mapping to second principal rejected at registration
    with pytest.raises(IdentitySecurityError, match="Ambiguous"):
        reg.register_binding(
            CertificatePrincipalBinding(principal_id="svc-2", fingerprints=(_fp(valid_der),))
        )

    # Expired certificate rejected
    with pytest.raises(IdentitySecurityError, match="expired"):
        reg.resolve_certificate(extract_certificate_identity(expired_der))

    # Wrong issuer rejected
    with pytest.raises(IdentitySecurityError, match="issuer"):
        reg.resolve_certificate(extract_certificate_identity(wrong_iss_der))

    # Valid certificate succeeds, then fails immediately after revocation
    assert reg.resolve_certificate(extract_certificate_identity(valid_der)).principal_id == "svc-1"
    reg.revoke_certificate(_fp(valid_der), reason="compromised")
    with pytest.raises(IdentitySecurityError, match="revoked"):
        reg.resolve_certificate(extract_certificate_identity(valid_der))


def test_spoofed_forwarded_cert_headers_and_shared_token_hardening(tmp_path: Path) -> None:
    """Spoofed cert headers are rejected; shared token cannot impersonate in REMOTE mode."""
    _, _, _, ca_cert, ca_key = _make_ca_and_cert(tmp_path / "ca", "CA")
    _, _, alice_der, _, _ = _make_ca_and_cert(tmp_path / "a", "alice", ca=(ca_cert, ca_key))

    store = ReceiptStore(tmp_path / "r.db")
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)
    server_mock = MagicMock()
    server_mock.services = AppServices(boundary)
    server_mock.auth_token = "shared-secret"
    server_mock.token_principals = None
    server_mock.cert_registry = None
    server_mock.require_client_cert = False
    server_mock.deployment_mode = DeploymentMode.REMOTE
    server_mock.allowed_hosts = ("gateway.actentra.internal",)
    server_mock.trusted_proxies = frozenset()

    # 1. Spoofed forwarded certificate header without TLS socket rejected
    for hdr_name in (
        "X-SSL-Client-Cert",
        "X-Forwarded-Client-Cert",
        "X-Client-Cert",
        "X-Actentra-Client-Cert",
    ):
        code, res = _dispatch_with_cert(
            server_mock,
            "/v1/receipts",
            headers={
                "Authorization": "Bearer shared-secret",
                hdr_name: "CN=admin,O=Trusted",
            },
            is_tls=False,
        )
        assert code == 403
        assert res["code"] == "mtls_spoofed_cert_header"

    # 2. Shared token in REMOTE mode cannot impersonate another principal via X-Actentra-Identity
    with pytest.raises(IdentitySecurityError, match="cannot impersonate"):
        resolve_http_caller_context(
            headers={
                "authorization": "Bearer shared-secret",
                "x-actentra-identity": "victim-operator",
            },
            expected_token="shared-secret",
            remote_addr="10.0.0.5",
            enforce_strict_shared_token=True,
        )

    # 3. Certificate substitution against token_principals cert_fingerprint rejected
    with pytest.raises(IdentitySecurityError, match="mismatch"):
        resolve_http_caller_context(
            headers={"authorization": "Bearer tok-pinned"},
            token_principals={
                "tok-pinned": {
                    "principal_id": "agent-pinned",
                    "cert_fingerprint": "sha256:" + "0" * 64,
                }
            },
            client_cert=extract_certificate_identity(alice_der),
        )


def test_certificate_and_token_rotation_lifecycle(tmp_path: Path) -> None:
    """Rotating certs and tokens invalidates old credentials and audits lifecycle events."""
    _, _, _, ca_cert, ca_key = _make_ca_and_cert(tmp_path / "ca", "CA")
    srv_cert, srv_key, _, _, _ = _make_ca_and_cert(
        tmp_path / "srv", "localhost", ca=(ca_cert, ca_key)
    )
    _, _, old_der, _, _ = _make_ca_and_cert(tmp_path / "old", "svc", ca=(ca_cert, ca_key))
    _, _, new_der, _, _ = _make_ca_and_cert(tmp_path / "new", "svc", ca=(ca_cert, ca_key))

    cert_reg = MTLSPrincipalRegistry.from_dict(
        {
            "svc-worker": {
                "fingerprints": [_fp(old_der)],
                "scopes": ["crossings:read", "receipts:read"],
            }
        }
    )
    store = ReceiptStore(tmp_path / "r.db")
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)
    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        token_principals={"tok-v1": {"principal_id": "svc-worker", "scopes": ["receipts:read"]}},
        cert_principals=cert_reg,
        certfile=srv_cert,
        keyfile=srv_key,
        ca_certs=tmp_path / "ca" / "CA.crt",
        require_client_cert=True,
        allowed_hosts=("localhost", "127.0.0.1"),
    )
    try:
        # Rotate certificate
        server.rotate_certificate("svc-worker", new_fingerprint=_fp(new_der), revoke_old=True)
        with pytest.raises(IdentitySecurityError, match="revoked"):
            cert_reg.resolve_certificate(extract_certificate_identity(old_der))
        assert (
            cert_reg.resolve_certificate(extract_certificate_identity(new_der)).principal_id
            == "svc-worker"
        )
        assert any(ev["event"] == "cert_rotated" for ev in cert_reg.audit_events())

        # Rotate token
        server.rotate_principal_token("tok-v1", "tok-v2")
        assert server.is_token_revoked("tok-v1") is True
        assert "tok-v1" not in (server.token_principals or {})
        assert "tok-v2" in (server.token_principals or {})
    finally:
        server.server_close()


def test_real_mtls_https_socket_principal_binding(tmp_path: Path) -> None:
    """Real TLS socket integration test: mismatched cert+token fails; matching succeeds."""
    ca_cert_p, _, _, ca_cert, ca_key = _make_ca_and_cert(tmp_path / "ca", "CA")
    srv_cert, srv_key, _, _, _ = _make_ca_and_cert(
        tmp_path / "srv", "127.0.0.1", ca=(ca_cert, ca_key)
    )
    alice_cert, alice_key, alice_der, _, _ = _make_ca_and_cert(
        tmp_path / "alice", "alice", ca=(ca_cert, ca_key)
    )
    _, _, bob_der, _, _ = _make_ca_and_cert(tmp_path / "bob", "bob", ca=(ca_cert, ca_key))

    cert_reg = MTLSPrincipalRegistry.from_dict(
        {
            "alice": {"fingerprints": [_fp(alice_der)], "scopes": ["receipts:read"]},
            "bob": {"fingerprints": [_fp(bob_der)], "scopes": ["receipts:read"]},
        }
    )
    store = ReceiptStore(tmp_path / "r.db")
    boundary = Boundary(policy=load_policy_yaml(_TEST_POLICY), receipt_store=store)
    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        token_principals={
            "tok-alice": {"principal_id": "alice", "scopes": ["receipts:read"]},
            "tok-bob": {"principal_id": "bob", "scopes": ["receipts:read"]},
        },
        cert_principals=cert_reg,
        certfile=srv_cert,
        keyfile=srv_key,
        ca_certs=ca_cert_p,
        require_client_cert=True,
        deployment_mode=DeploymentMode.REMOTE,
        allowed_hosts=("127.0.0.1", "localhost"),
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        ctx = ssl.create_default_context(cafile=str(ca_cert_p))
        ctx.check_hostname = False
        ctx.load_cert_chain(certfile=str(alice_cert), keyfile=str(alice_key))

        # 1. Alice cert + Bob token -> 403 Forbidden
        conn1 = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5.0)
        conn1.request(
            "GET",
            "/v1/receipts",
            headers={"Host": "127.0.0.1", "Authorization": "Bearer tok-bob"},
        )
        r1 = conn1.getresponse()
        assert r1.status == 403
        conn1.close()

        # 2. Alice cert + Alice token -> 200 OK
        conn2 = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5.0)
        conn2.request(
            "GET",
            "/v1/receipts",
            headers={"Host": "127.0.0.1", "Authorization": "Bearer tok-alice"},
        )
        r2 = conn2.getresponse()
        assert r2.status == 200
        conn2.close()
    except OSError as exc:
        if "10013" in str(exc) or "forbidden" in str(exc).lower():
            pytest.skip(f"Loopback socket access restricted by sandbox: {exc}")
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
