"""Tests for Phase 5 production trust profiles, external audit anchoring, and key custody."""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from actentra.boundary import Boundary
from actentra_core.checkpoints import (
    CheckpointAnchor,
    CheckpointError,
    FileCheckpointAnchor,
    KeyRing,
    MemoryCheckpointAnchor,
    SecurityProfile,
    SignedCheckpoint,
    assess_audit_guarantees,
    create_key_record,
    generate_ed25519_keypair,
)
from actentra_core.identity import MTLSPrincipalRegistry
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.http_service import DeploymentMode, create_gateway_server
from actentra_gateway.services import AppServices

_POLICY = """
version: 1
policy_id: test-p5-trust
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-read
    match: { verb: read }
    verdict: allow
"""


class _FailingAnchor(CheckpointAnchor):
    def save_checkpoint(self, checkpoint: SignedCheckpoint) -> None:
        raise CheckpointError("External anchor storage unreachable")

    def list_checkpoints(self) -> list[SignedCheckpoint]:
        raise CheckpointError("External anchor storage unreachable")

    def get_latest_checkpoint(self) -> SignedCheckpoint | None:
        raise CheckpointError("External anchor storage unreachable")


def _make_cert(out_dir: Path, cn: str) -> tuple[Path, Path, bytes]:
    out_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cp = out_dir / f"{cn}.crt"
    kp = out_dir / f"{cn}.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return cp, kp, der


def test_local_profiles_never_claim_externally_anchored(tmp_path: Path) -> None:
    """local_dev and local_trusted explicitly report externally_anchored=False without anchor."""
    db_path = tmp_path / "db" / "receipts.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(policy=load_policy_yaml(_POLICY), receipt_store=store)

    for profile in (SecurityProfile.LOCAL_DEV, SecurityProfile.LOCAL_TRUSTED):
        svc = AppServices(boundary, security_profile=profile)
        health = svc.get_health()
        guarantees = health["audit_guarantees"]
        assert health["security_profile"] == profile.value
        assert guarantees["externally_anchored"] is False
        assert guarantees["protects_against_local_db_rewrite"] is False
        assert guarantees["protects_against_compromised_host"] is False
        assert guarantees["audit_tier"] == "hash_chain_only"


def test_production_profiles_fail_closed_when_misconfigured(tmp_path: Path) -> None:
    """controlled_pilot and external_production reject missing anchor or bad keys."""
    db_dir = tmp_path / "db"
    db_path = db_dir / "receipts.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(policy=load_policy_yaml(_POLICY), receipt_store=store)
    _, pub_pem = generate_ed25519_keypair()
    ring = KeyRing([create_key_record(pub_pem)])
    sep_anchor = FileCheckpointAnchor(tmp_path / "external_anchor")

    # 1. Missing anchor -> CheckpointError
    for profile in (SecurityProfile.CONTROLLED_PILOT, SecurityProfile.EXTERNAL_PRODUCTION):
        with pytest.raises(CheckpointError, match="CheckpointAnchor"):
            AppServices(boundary, security_profile=profile, key_ring=ring)

    # 2. MemoryCheckpointAnchor prohibited in external_production
    with pytest.raises(CheckpointError, match="MemoryCheckpointAnchor"):
        AppServices(
            boundary,
            security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
            checkpoint_anchor=MemoryCheckpointAnchor(),
            key_ring=ring,
        )

    # 3. Same-directory FileCheckpointAnchor violates custody separation in external_production
    with pytest.raises(CheckpointError, match="custody separation"):
        AppServices(
            boundary,
            security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
            checkpoint_anchor=FileCheckpointAnchor(db_dir),
            key_ring=ring,
        )

    # 4. Missing KeyRing or no active keys -> CheckpointError
    with pytest.raises(CheckpointError, match="KeyRing"):
        AppServices(
            boundary,
            security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
            checkpoint_anchor=sep_anchor,
            key_ring=None,
        )
    revoked_ring = KeyRing([create_key_record(pub_pem, status="revoked")])
    with pytest.raises(CheckpointError, match="active signing key"):
        AppServices(
            boundary,
            security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
            checkpoint_anchor=sep_anchor,
            key_ring=revoked_ring,
        )

    # 5. Unavailable external anchor -> CheckpointError
    with pytest.raises(CheckpointError, match="unavailable"):
        AppServices(
            boundary,
            security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
            checkpoint_anchor=_FailingAnchor(),
            key_ring=ring,
        )


def test_gateway_external_production_rejects_shared_token_and_missing_mtls(tmp_path: Path) -> None:
    """EXTERNAL_PRODUCTION gateway refuses shared auth_token alone or missing mTLS."""
    db_path = tmp_path / "db" / "receipts.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(policy=load_policy_yaml(_POLICY), receipt_store=store)
    _, pub_pem = generate_ed25519_keypair()
    ring = KeyRing([create_key_record(pub_pem)])
    anchor = FileCheckpointAnchor(tmp_path / "anchor")
    srv_cert, srv_key, cli_der = _make_cert(tmp_path / "certs", "localhost")
    fp = f"sha256:{hashlib.sha256(cli_der).hexdigest().lower()}"

    # 1. Shared auth_token only -> rejected
    with pytest.raises(ValueError, match="individual principal"):
        create_gateway_server(
            boundary,
            host="127.0.0.1",
            port=0,
            auth_token="shared-op-secret",
            certfile=srv_cert,
            keyfile=srv_key,
            ca_certs=srv_cert,
            require_client_cert=True,
            deployment_mode=DeploymentMode.REMOTE,
            security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
            checkpoint_anchor=anchor,
            key_ring=ring,
        )

    # 2. token_principals without mTLS cert_principals -> rejected
    with pytest.raises(ValueError, match="require_client_cert=True and cert_principals"):
        create_gateway_server(
            boundary,
            host="127.0.0.1",
            port=0,
            token_principals={"tok-1": {"principal_id": "svc-1"}},
            certfile=srv_cert,
            keyfile=srv_key,
            deployment_mode=DeploymentMode.REMOTE,
            security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
            checkpoint_anchor=anchor,
            key_ring=ring,
        )

    # 3. Full valid external_production configuration succeeds
    server = create_gateway_server(
        boundary,
        host="127.0.0.1",
        port=0,
        token_principals={"tok-1": {"principal_id": "svc-1", "scopes": ["receipts:read"]}},
        cert_principals=MTLSPrincipalRegistry.from_dict({"svc-1": {"fingerprints": [fp]}}),
        certfile=srv_cert,
        keyfile=srv_key,
        ca_certs=srv_cert,
        require_client_cert=True,
        deployment_mode=DeploymentMode.REMOTE,
        security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
        checkpoint_anchor=anchor,
        key_ring=ring,
        allowed_hosts=("127.0.0.1", "localhost"),
    )
    server.server_close()


def test_checkpoint_tampering_rollback_key_rotation_and_revocation(tmp_path: Path) -> None:
    """Verify fail-closed detection for tampering, rollback, anchor failure, and key rotation."""
    db_path = tmp_path / "db" / "receipts.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(policy=load_policy_yaml(_POLICY), receipt_store=store)
    priv1, pub1 = generate_ed25519_keypair()
    priv2, pub2 = generate_ed25519_keypair()
    rec1 = create_key_record(pub1)
    ring = KeyRing([rec1])
    anchor = FileCheckpointAnchor(tmp_path / "anchor")

    svc = AppServices(
        boundary,
        security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
        checkpoint_anchor=anchor,
        key_ring=ring,
    )
    svc.submit_crossing({"tool": "fs.read", "verb": "read", "resource": "path:C:/w/a.txt"})
    cp1 = svc.create_checkpoint(priv1)
    assert cp1.checkpoint_seq == 1

    # Valid anchored trail
    ver_ok = svc.verify_audit_log()
    assert ver_ok["ok"] is True
    assert ver_ok["externally_anchored"] is True
    assert ver_ok["checkpoints_verified"] == 1
    assert ver_ok["audit_guarantees"]["protects_against_local_db_rewrite"] is True
    assert ver_ok["audit_guarantees"]["protects_against_compromised_host"] is False

    # Key rotation: retire key1, activate key2
    rec2 = create_key_record(pub2)
    ring.rotate_key(rec2, retire_existing=True)
    svc.submit_crossing({"tool": "fs.read", "verb": "read", "resource": "path:C:/w/b.txt"})
    cp2 = svc.create_checkpoint(priv2)
    assert cp2.checkpoint_seq == 2
    assert svc.verify_audit_log()["ok"] is True

    # Signing with retired/revoked key1 after revocation fails closed
    ring.revoke_key(rec1.key_id, reason="rotated_and_revoked")
    with pytest.raises(CheckpointError, match="rejected by key ring"):
        svc.create_checkpoint(priv1)

    # Tamper with checkpoint #2 signature on anchor -> fail closed
    cp_files = sorted((tmp_path / "anchor").glob("checkpoint_00000002_*.json"))
    raw_cp = json.loads(cp_files[0].read_text(encoding="utf-8"))
    raw_cp["head_hash"] = "sha256:" + "0" * 64
    cp_files[0].write_text(json.dumps(raw_cp), encoding="utf-8")

    ver_bad = svc.verify_audit_log()
    assert ver_bad["ok"] is False
    assert ver_bad["externally_anchored"] is False
    assert ver_bad["divergence_type"] == "SIGNATURE_FORGERY"
    assert svc.get_health()["status"] == "degraded"

    # Anchor unavailable -> assess_audit_guarantees reports unverified & externally_anchored=False
    g_unavail = assess_audit_guarantees(
        db_path,
        security_profile=SecurityProfile.EXTERNAL_PRODUCTION,
        checkpoint_anchor=_FailingAnchor(),
        key_ring=ring,
    )
    assert g_unavail["externally_anchored"] is False
    assert g_unavail["errors"]


def test_audit_outputs_do_not_leak_secrets(tmp_path: Path) -> None:
    """Health, verify, and exported audit bundle must not contain private keys or bearer secrets."""
    db_path = tmp_path / "db" / "receipts.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(policy=load_policy_yaml(_POLICY), receipt_store=store)
    priv_pem, pub_pem = generate_ed25519_keypair()
    ring = KeyRing([create_key_record(pub_pem)])
    anchor = FileCheckpointAnchor(tmp_path / "anchor")
    svc = AppServices(
        boundary,
        security_profile=SecurityProfile.CONTROLLED_PILOT,
        checkpoint_anchor=anchor,
        key_ring=ring,
    )
    svc.create_checkpoint(priv_pem)

    bundle: dict[str, Any] = svc.export_audit_bundle()
    serialized = json.dumps(
        {"health": svc.get_health(), "verify": svc.verify_audit_log(), "bundle": bundle}
    )
    assert "PRIVATE KEY" not in serialized
    assert priv_pem.decode("utf-8") not in serialized
    assert bundle["audit_guarantees"]["externally_anchored"] is True
