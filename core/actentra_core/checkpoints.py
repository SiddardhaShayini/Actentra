"""Ed25519 signed checkpoints for tamper-evident Actentra receipt chains."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from actentra_core.canonicalize import canonicalize_json
from actentra_core.envelope import utc_now_iso
from actentra_core.receipts import ReceiptError, ReceiptStore, verify_log


class CheckpointError(RuntimeError):
    """Raised when checkpoint signing or verification fails."""


@dataclass(frozen=True, slots=True)
class SignedCheckpoint:
    version: int
    seq: int
    head_hash: str
    total_records: int
    ts: str
    key_id: str
    signature_b64: str

    def payload_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "seq": self.seq,
            "head_hash": self.head_hash,
            "total_records": self.total_records,
            "ts": self.ts,
            "key_id": self.key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["signature_b64"] = self.signature_b64
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedCheckpoint:
        try:
            return cls(
                version=int(data["version"]),
                seq=int(data["seq"]),
                head_hash=str(data["head_hash"]),
                total_records=int(data["total_records"]),
                ts=str(data["ts"]),
                key_id=str(data["key_id"]),
                signature_b64=str(data["signature_b64"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckpointError(f"Invalid checkpoint structure: {exc}") from exc


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate an unencrypted Ed25519 keypair as (private_pem, public_pem)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def compute_key_id(public_key: Ed25519PublicKey) -> str:
    """Compute a short deterministic key identifier from an Ed25519 public key."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def sign_checkpoint(db_path: str | Path, private_key_pem: bytes) -> SignedCheckpoint:
    """Verify the receipt log and sign a checkpoint at its current head."""
    vr = verify_log(db_path)
    if not vr.ok:
        raise CheckpointError(f"Cannot checkpoint invalid receipt log: {'; '.join(vr.errors)}")

    try:
        loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as exc:
        raise CheckpointError(f"Invalid Ed25519 private key: {exc}") from exc
    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise CheckpointError("Private key must be Ed25519")

    key_id = compute_key_id(loaded_key.public_key())
    ts = utc_now_iso()
    payload = {
        "version": 1,
        "seq": vr.total_records,
        "head_hash": vr.last_hash,
        "total_records": vr.total_records,
        "ts": ts,
        "key_id": key_id,
    }
    msg = canonicalize_json(payload).encode("utf-8")
    sig_b64 = base64.b64encode(loaded_key.sign(msg)).decode("ascii")
    return SignedCheckpoint(
        version=1,
        seq=vr.total_records,
        head_hash=vr.last_hash,
        total_records=vr.total_records,
        ts=ts,
        key_id=key_id,
        signature_b64=sig_b64,
    )


def verify_checkpoint(
    checkpoint: SignedCheckpoint,
    public_key_pem: bytes,
    *,
    db_path: str | Path | None = None,
) -> tuple[bool, str]:
    """Verify a checkpoint's Ed25519 signature and optionally anchor it against ``db_path``."""
    try:
        loaded_pub = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:
        return False, f"Invalid public key: {exc}"
    if not isinstance(loaded_pub, Ed25519PublicKey):
        return False, "Public key must be Ed25519"

    expected_key_id = compute_key_id(loaded_pub)
    if checkpoint.key_id != expected_key_id:
        return False, f"Key ID mismatch (expected {expected_key_id}, got {checkpoint.key_id})"

    try:
        sig_bytes = base64.b64decode(checkpoint.signature_b64, validate=True)
    except ValueError as exc:
        return False, f"Invalid base64 signature: {exc}"

    msg = canonicalize_json(checkpoint.payload_dict()).encode("utf-8")
    try:
        loaded_pub.verify(sig_bytes, msg)
    except InvalidSignature:
        return False, "Ed25519 signature verification failed"

    if db_path is not None:
        vr = verify_log(db_path)
        if not vr.ok:
            return False, f"Receipt log integrity check failed: {'; '.join(vr.errors)}"
        if vr.total_records < checkpoint.seq:
            return False, (
                f"Receipt log truncated: has {vr.total_records} records, "
                f"checkpoint requires >= {checkpoint.seq}"
            )
        try:
            records = ReceiptStore(db_path).iter_records()
        except ReceiptError as exc:
            return False, f"Unable to read receipt log: {exc}"
        if checkpoint.seq == 0:
            if checkpoint.head_hash != vr.last_hash and records:
                return False, "Checkpoint seq=0 does not match non-empty log"
        else:
            rec = records[checkpoint.seq - 1]
            if rec.seq != checkpoint.seq or rec.entry_hash != checkpoint.head_hash:
                return False, (
                    f"Checkpoint head mismatch at seq={checkpoint.seq}: "
                    f"log has {rec.entry_hash}, checkpoint has {checkpoint.head_hash}"
                )

    return True, "OK"


def write_checkpoint(checkpoint: SignedCheckpoint, out_path: str | Path) -> None:
    """Persist a SignedCheckpoint to disk as formatted JSON."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(checkpoint.to_dict(), indent=2) + "\n", encoding="utf-8")


def load_checkpoint(path: str | Path) -> SignedCheckpoint:
    """Load a SignedCheckpoint JSON file from disk."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckpointError(f"Unable to read checkpoint {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CheckpointError("Checkpoint JSON root must be an object")
    return SignedCheckpoint.from_dict(data)
