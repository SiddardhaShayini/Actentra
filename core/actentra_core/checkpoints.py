"""Ed25519 signed checkpoints and external audit anchoring for Actentra.

Provides:
- Cryptographic key management (KeyRecord, KeyRing, key rotation and revocation).
- Chained, tamper-evident SignedCheckpoint (with monotonic sequence, prev_checkpoint_hash).
- External append-only CheckpointAnchor (FileCheckpointAnchor, MemoryCheckpointAnchor).
- Unified AuditTrailVerificationResult and verify_audit_trail() cross-checking SQLite.
- Offline audit bundle verification (verify_audit_bundle).
"""

from __future__ import annotations

import abc
import base64
import dataclasses
import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from actentra_core.canonicalize import canonicalize_json, hash_canonical
from actentra_core.envelope import utc_now_iso
from actentra_core.receipts import GENESIS_HASH, ReceiptError, ReceiptStore, verify_log

GENESIS_CHECKPOINT_HASH = "sha256:" + ("0" * 64)
KeyStatus = Literal["active", "retired", "revoked"]
_VALID_KEY_STATUSES = frozenset({"active", "retired", "revoked"})

DivergenceType = Literal[
    "CHAIN_REWRITE",
    "ROLLBACK",
    "TAIL_TRUNCATION",
    "CHECKPOINT_TAMPERING",
    "SIGNATURE_FORGERY",
    "UNTRUSTED_KEY",
    "REVOKED_KEY",
    "KEY_EXPIRED",
    "RECEIPT_TAMPERING",
    "MISSING_CHECKPOINTS",
]


class CheckpointError(RuntimeError):
    """Raised when checkpoint signing, persistence, or verification fails."""


# -----------------------------------------------------------------------------
# 1. Key Management: KeyRecord and KeyRing
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyRecord:
    """Public key record with lifecycle metadata, validity window, and revocation."""

    key_id: str
    public_key_pem: str
    status: KeyStatus
    valid_from: str
    valid_until: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "status": self.status,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyRecord:
        status_val = str(data.get("status", "active"))
        if status_val not in _VALID_KEY_STATUSES:
            raise CheckpointError(f"Invalid key status '{status_val}'")
        rev_reason = str(data["revocation_reason"]) if data.get("revocation_reason") else None
        return cls(
            key_id=str(data["key_id"]),
            public_key_pem=str(data["public_key_pem"]),
            status=status_val,  # type: ignore[arg-type]
            valid_from=str(data["valid_from"]),
            valid_until=str(data["valid_until"]) if data.get("valid_until") else None,
            revoked_at=str(data["revoked_at"]) if data.get("revoked_at") else None,
            revocation_reason=rev_reason,
        )


class KeyRing:
    """Manifest of trusted public keys supporting rotation and revocation."""

    def __init__(self, keys: list[KeyRecord] | None = None) -> None:
        self._keys: dict[str, KeyRecord] = {}
        if keys:
            for k in keys:
                self.add_key(k)

    def add_key(self, record: KeyRecord) -> None:
        self._keys[record.key_id] = record

    def get_key(self, key_id: str) -> KeyRecord | None:
        return self._keys.get(key_id)

    def get_active_key(self) -> KeyRecord | None:
        for k in self._keys.values():
            if k.status == "active":
                return k
        return None

    def rotate_key(self, new_key: KeyRecord, *, retire_existing: bool = True) -> None:
        """Rotate the active signing key, retiring any currently active keys."""
        if retire_existing:
            now_iso = utc_now_iso()
            for kid, k in list(self._keys.items()):
                if k.status == "active":
                    retired = KeyRecord(
                        key_id=k.key_id,
                        public_key_pem=k.public_key_pem,
                        status="retired",
                        valid_from=k.valid_from,
                        valid_until=k.valid_until or now_iso,
                        revoked_at=k.revoked_at,
                        revocation_reason=k.revocation_reason,
                    )
                    self._keys[kid] = retired
        self.add_key(new_key)

    def revoke_key(
        self,
        key_id: str,
        *,
        reason: str,
        revoked_at: str | None = None,
    ) -> None:
        """Revoke a compromised or retired key with timestamp and rationale."""
        k = self._keys.get(key_id)
        if k is None:
            raise CheckpointError(f"Cannot revoke unknown key '{key_id}'")
        rev_iso = revoked_at or utc_now_iso()
        revoked = KeyRecord(
            key_id=k.key_id,
            public_key_pem=k.public_key_pem,
            status="revoked",
            valid_from=k.valid_from,
            valid_until=k.valid_until,
            revoked_at=rev_iso,
            revocation_reason=reason,
        )
        self._keys[key_id] = revoked

    def validate_key_at_time(self, key_id: str, ts: str) -> tuple[bool, str]:
        """Validate whether a key was authorized to sign at timestamp ``ts``."""
        k = self.get_key(key_id)
        if k is None:
            return False, f"Key '{key_id}' not found in trusted key ring"

        if ts < k.valid_from:
            return False, f"Key '{key_id}' not valid yet at {ts} (valid_from {k.valid_from})"

        if k.valid_until and ts > k.valid_until:
            return False, f"Key '{key_id}' expired at {k.valid_until} (checked {ts})"

        if k.status == "revoked":
            if k.revoked_at and ts >= k.revoked_at:
                return (
                    False,
                    f"Key '{key_id}' was revoked at {k.revoked_at} (reason: {k.revocation_reason})",
                )
            if not k.revoked_at:
                return False, f"Key '{key_id}' is marked revoked (reason: {k.revocation_reason})"

        return True, "OK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "keys": [k.to_dict() for k in self._keys.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyRing:
        raw_keys = data.get("keys", [])
        return cls([KeyRecord.from_dict(k) for k in raw_keys])

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> KeyRing:
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            raise CheckpointError(f"Failed to load key ring from {p}: {exc}") from exc
        return cls.from_dict(data)


# -----------------------------------------------------------------------------
# 2. Signed Checkpoint Structure & Chaining
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SignedCheckpoint:
    """Cryptographically signed, hash-chained checkpoint anchoring receipt log head."""

    version: int
    seq: int
    head_hash: str
    total_records: int
    ts: str
    key_id: str
    signature_b64: str
    checkpoint_id: str = ""
    checkpoint_seq: int = 1
    prev_checkpoint_hash: str = GENESIS_CHECKPOINT_HASH

    @property
    def head_seq(self) -> int:
        """Alias for seq: receipt log sequence anchored by this checkpoint."""
        return self.seq

    @property
    def created_at(self) -> str:
        """Alias for ts: timestamp when checkpoint was created."""
        return self.ts

    def payload_dict(self) -> dict[str, Any]:
        """Canonical dictionary representation of signed fields."""
        if self.version == 1:
            return {
                "version": 1,
                "seq": self.seq,
                "head_hash": self.head_hash,
                "total_records": self.total_records,
                "ts": self.ts,
                "key_id": self.key_id,
            }
        return {
            "version": self.version,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_seq": self.checkpoint_seq,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "prev_checkpoint_hash": self.prev_checkpoint_hash,
            "created_at": self.created_at,
            "key_id": self.key_id,
        }

    def compute_checkpoint_hash(self) -> str:
        """Compute the SHA-256 hash of the canonical checkpoint payload."""
        return hash_canonical(self.payload_dict())

    def to_dict(self) -> dict[str, Any]:
        data = self.payload_dict()
        data["signature_b64"] = self.signature_b64
        data["total_records"] = self.total_records
        data["seq"] = self.seq
        data["ts"] = self.ts
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedCheckpoint:
        try:
            v = int(data.get("version", 1))
            seq_val = int(data.get("head_seq", data.get("seq", 0)))
            ts_val = str(data.get("created_at", data.get("ts", "")))
            tot_val = int(data.get("total_records", seq_val))
            cid_val = str(data.get("checkpoint_id", f"cp_{seq_val}"))
            cp_seq_val = int(data.get("checkpoint_seq", 1))
            prev_cp_val = str(data.get("prev_checkpoint_hash", GENESIS_CHECKPOINT_HASH))

            return cls(
                version=v,
                seq=seq_val,
                head_hash=str(data["head_hash"]),
                total_records=tot_val,
                ts=ts_val,
                key_id=str(data["key_id"]),
                signature_b64=str(data["signature_b64"]),
                checkpoint_id=cid_val,
                checkpoint_seq=cp_seq_val,
                prev_checkpoint_hash=prev_cp_val,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckpointError(f"Invalid checkpoint structure: {exc}") from exc


# -----------------------------------------------------------------------------
# 3. External Checkpoint Sinks & Anchors
# -----------------------------------------------------------------------------


class CheckpointAnchor(abc.ABC):
    """Abstract append-only destination for durable off-host checkpoint anchoring."""

    @abc.abstractmethod
    def save_checkpoint(self, checkpoint: SignedCheckpoint) -> None:
        """Persist a new checkpoint, enforcing monotonic sequence and prev_hash continuity."""

    @abc.abstractmethod
    def list_checkpoints(self) -> list[SignedCheckpoint]:
        """Return all checkpoints ordered by checkpoint_seq ascending."""

    @abc.abstractmethod
    def get_latest_checkpoint(self) -> SignedCheckpoint | None:
        """Return the highest-sequence checkpoint, or None if empty."""


class MemoryCheckpointAnchor(CheckpointAnchor):
    """Thread-safe in-memory checkpoint anchor for testing and ephemeral workflows."""

    def __init__(self) -> None:
        self._checkpoints: list[SignedCheckpoint] = []
        self._lock = threading.Lock()

    def save_checkpoint(self, checkpoint: SignedCheckpoint) -> None:
        with self._lock:
            if self._checkpoints:
                latest = self._checkpoints[-1]
                expected_seq = latest.checkpoint_seq + 1
                if checkpoint.checkpoint_seq != expected_seq:
                    raise CheckpointError(
                        f"Non-monotonic sequence: expected {expected_seq}, "
                        f"got {checkpoint.checkpoint_seq}"
                    )
                expected_prev = latest.compute_checkpoint_hash()
                if checkpoint.prev_checkpoint_hash != expected_prev:
                    raise CheckpointError(
                        f"Checkpoint prev_hash mismatch: expected {expected_prev}, "
                        f"got {checkpoint.prev_checkpoint_hash}"
                    )
            else:
                if checkpoint.checkpoint_seq != 1:
                    raise CheckpointError(
                        f"First checkpoint must have checkpoint_seq=1, "
                        f"got {checkpoint.checkpoint_seq}"
                    )
                if checkpoint.prev_checkpoint_hash != GENESIS_CHECKPOINT_HASH:
                    raise CheckpointError(
                        f"First checkpoint must reference GENESIS_CHECKPOINT_HASH, "
                        f"got {checkpoint.prev_checkpoint_hash}"
                    )
            self._checkpoints.append(checkpoint)

    def list_checkpoints(self) -> list[SignedCheckpoint]:
        with self._lock:
            return list(self._checkpoints)

    def get_latest_checkpoint(self) -> SignedCheckpoint | None:
        with self._lock:
            return self._checkpoints[-1] if self._checkpoints else None


class FileCheckpointAnchor(CheckpointAnchor):
    """Durable file/directory based checkpoint anchor separate from the SQLite database."""

    def __init__(self, anchor_dir: str | Path) -> None:
        self._dir = Path(anchor_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def anchor_dir(self) -> Path:
        return self._dir

    def list_checkpoints(self) -> list[SignedCheckpoint]:
        with self._lock:
            return self._list_internal()

    def _list_internal(self) -> list[SignedCheckpoint]:
        cps: list[SignedCheckpoint] = []
        for file in sorted(self._dir.glob("checkpoint_*.json")):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                cps.append(SignedCheckpoint.from_dict(data))
            except Exception as exc:
                raise CheckpointError(f"Corrupt checkpoint file {file}: {exc}") from exc
        cps.sort(key=lambda c: c.checkpoint_seq)
        return cps

    def get_latest_checkpoint(self) -> SignedCheckpoint | None:
        cps = self.list_checkpoints()
        return cps[-1] if cps else None

    def save_checkpoint(self, checkpoint: SignedCheckpoint) -> None:
        with self._lock:
            existing = self._list_internal()
            if existing:
                latest = existing[-1]
                expected_seq = latest.checkpoint_seq + 1
                if checkpoint.checkpoint_seq != expected_seq:
                    raise CheckpointError(
                        f"Non-monotonic sequence: expected {expected_seq}, "
                        f"got {checkpoint.checkpoint_seq}"
                    )
                expected_prev = latest.compute_checkpoint_hash()
                if checkpoint.prev_checkpoint_hash != expected_prev:
                    raise CheckpointError(
                        f"Checkpoint prev_hash mismatch: expected {expected_prev}, "
                        f"got {checkpoint.prev_checkpoint_hash}"
                    )
            else:
                if checkpoint.checkpoint_seq != 1:
                    raise CheckpointError(
                        f"First checkpoint must have checkpoint_seq=1, "
                        f"got {checkpoint.checkpoint_seq}"
                    )
                if checkpoint.prev_checkpoint_hash != GENESIS_CHECKPOINT_HASH:
                    raise CheckpointError(
                        f"First checkpoint must reference GENESIS_CHECKPOINT_HASH, "
                        f"got {checkpoint.prev_checkpoint_hash}"
                    )

            target_name = (
                f"checkpoint_{checkpoint.checkpoint_seq:08d}_{checkpoint.checkpoint_id}.json"
            )
            target_path = self._dir / target_name
            temp_path = self._dir / f".tmp_{uuid.uuid4().hex}_{target_name}"

            content = json.dumps(checkpoint.to_dict(), indent=2) + "\n"
            temp_path.write_text(content, encoding="utf-8")
            os.replace(temp_path, target_path)


# -----------------------------------------------------------------------------
# 4. Cryptographic Key Helpers
# -----------------------------------------------------------------------------


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


def create_key_record(
    public_key_pem: bytes | str,
    *,
    status: KeyStatus = "active",
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> KeyRecord:
    """Helper to construct a KeyRecord from public key bytes or string."""
    pem_str = (
        public_key_pem.decode("utf-8")
        if isinstance(public_key_pem, bytes)
        else public_key_pem
    )
    loaded = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    if not isinstance(loaded, Ed25519PublicKey):
        raise CheckpointError("Public key must be Ed25519")
    kid = compute_key_id(loaded)
    return KeyRecord(
        key_id=kid,
        public_key_pem=pem_str,
        status=status,
        valid_from=valid_from or utc_now_iso(),
        valid_until=valid_until,
    )


# -----------------------------------------------------------------------------
# 5. Checkpoint Signing & Verification
# -----------------------------------------------------------------------------


def sign_checkpoint(
    db_path: str | Path,
    private_key_pem: bytes,
    *,
    anchor: CheckpointAnchor | None = None,
    key_ring: KeyRing | None = None,
    checkpoint_id: str | None = None,
    version: int = 2,
) -> SignedCheckpoint:
    """Verify receipt log integrity, construct a chained checkpoint, and sign it."""
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

    if key_ring is not None:
        ok_key, reason_key = key_ring.validate_key_at_time(key_id, ts)
        if not ok_key:
            raise CheckpointError(f"Signing key '{key_id}' rejected by key ring: {reason_key}")

    latest: SignedCheckpoint | None = None
    if anchor is not None:
        latest = anchor.get_latest_checkpoint()

    if latest is None:
        checkpoint_seq = 1
        prev_cp_hash = GENESIS_CHECKPOINT_HASH
    else:
        checkpoint_seq = latest.checkpoint_seq + 1
        prev_cp_hash = latest.compute_checkpoint_hash()

    cid = checkpoint_id or f"cp_{uuid.uuid4().hex[:12]}"
    payload: dict[str, Any]
    if version == 1:
        payload = {
            "version": 1,
            "seq": vr.total_records,
            "head_hash": vr.last_hash,
            "total_records": vr.total_records,
            "ts": ts,
            "key_id": key_id,
        }
    else:
        payload = {
            "version": version,
            "checkpoint_id": cid,
            "checkpoint_seq": checkpoint_seq,
            "head_seq": vr.total_records,
            "head_hash": vr.last_hash,
            "prev_checkpoint_hash": prev_cp_hash,
            "created_at": ts,
            "key_id": key_id,
        }

    msg = canonicalize_json(payload).encode("utf-8")
    sig_b64 = base64.b64encode(loaded_key.sign(msg)).decode("ascii")

    cp = SignedCheckpoint(
        version=version,
        seq=vr.total_records,
        head_hash=vr.last_hash,
        total_records=vr.total_records,
        ts=ts,
        key_id=key_id,
        signature_b64=sig_b64,
        checkpoint_id=cid,
        checkpoint_seq=checkpoint_seq,
        prev_checkpoint_hash=prev_cp_hash,
    )

    if anchor is not None:
        anchor.save_checkpoint(cp)

    return cp


def verify_checkpoint(
    checkpoint: SignedCheckpoint,
    public_key_pem: bytes | KeyRing,
    *,
    db_path: str | Path | None = None,
) -> tuple[bool, str]:
    """Verify a checkpoint's Ed25519 signature and optionally anchor it against ``db_path``."""
    key_pem: bytes
    if isinstance(public_key_pem, KeyRing):
        rec = public_key_pem.get_key(checkpoint.key_id)
        if rec is None:
            return False, f"Key ID '{checkpoint.key_id}' not found in key ring"
        ok_time, msg_time = public_key_pem.validate_key_at_time(
            checkpoint.key_id, checkpoint.created_at
        )
        if not ok_time:
            return False, f"Key validation failed: {msg_time}"
        key_pem = rec.public_key_pem.encode("utf-8")
    else:
        key_pem = public_key_pem

    try:
        loaded_pub = serialization.load_pem_public_key(key_pem)
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
        if vr.total_records < checkpoint.head_seq:
            return False, (
                f"Receipt log truncated: has {vr.total_records} records, "
                f"checkpoint requires >= {checkpoint.head_seq}"
            )
        try:
            records = ReceiptStore(db_path).iter_records()
        except ReceiptError as exc:
            return False, f"Unable to read receipt log: {exc}"
        if checkpoint.head_seq == 0:
            if checkpoint.head_hash != vr.last_hash and records:
                return False, "Checkpoint head_seq=0 does not match non-empty log"
        else:
            receipt_rec = records[checkpoint.head_seq - 1]
            if (
                receipt_rec.seq != checkpoint.head_seq
                or receipt_rec.entry_hash != checkpoint.head_hash
            ):
                return False, (
                    f"Checkpoint head mismatch at seq={checkpoint.head_seq}: "
                    f"log has {receipt_rec.entry_hash}, checkpoint has {checkpoint.head_hash}"
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


# -----------------------------------------------------------------------------
# 6. Unified Audit Trail Verification Tooling
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditTrailVerificationResult:
    """Comprehensive, machine-readable verification result for audit trail and anchors."""

    ok: bool
    receipts_verified: int
    checkpoints_verified: int
    head_seq: int
    head_hash: str
    latest_checkpoint_seq: int
    divergence_type: DivergenceType | None = None
    errors: tuple[str, ...] = ()
    details: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "receipts_verified": self.receipts_verified,
            "checkpoints_verified": self.checkpoints_verified,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "latest_checkpoint_seq": self.latest_checkpoint_seq,
            "divergence_type": self.divergence_type,
            "errors": list(self.errors),
            "details": self.details,
        }


def verify_audit_trail(
    db_path: str | Path,
    anchor: CheckpointAnchor,
    key_ring: KeyRing | bytes,
    *,
    verify_envelopes: bool = False,
    require_checkpoints: bool = True,
) -> AuditTrailVerificationResult:
    """Independently verify receipt hash chain, external checkpoint continuity, and anchoring."""
    path = Path(db_path)
    if not path.exists():
        return AuditTrailVerificationResult(
            ok=False,
            receipts_verified=0,
            checkpoints_verified=0,
            head_seq=0,
            head_hash=GENESIS_HASH,
            latest_checkpoint_seq=0,
            divergence_type="RECEIPT_TAMPERING",
            errors=(f"Receipt database not found: {path}",),
        )

    # 1. Verify internal SQLite receipt log
    vr = verify_log(db_path, verify_envelopes=verify_envelopes)
    if not vr.ok:
        return AuditTrailVerificationResult(
            ok=False,
            receipts_verified=vr.total_records,
            checkpoints_verified=0,
            head_seq=vr.total_records,
            head_hash=vr.last_hash,
            latest_checkpoint_seq=0,
            divergence_type="RECEIPT_TAMPERING",
            errors=vr.errors,
        )

    # 2. Fetch external checkpoints
    checkpoints = anchor.list_checkpoints()
    if not checkpoints:
        if require_checkpoints:
            return AuditTrailVerificationResult(
                ok=False,
                receipts_verified=vr.total_records,
                checkpoints_verified=0,
                head_seq=vr.total_records,
                head_hash=vr.last_hash,
                latest_checkpoint_seq=0,
                divergence_type="MISSING_CHECKPOINTS",
                errors=("No external checkpoints found in anchor",),
            )
        return AuditTrailVerificationResult(
            ok=True,
            receipts_verified=vr.total_records,
            checkpoints_verified=0,
            head_seq=vr.total_records,
            head_hash=vr.last_hash,
            latest_checkpoint_seq=0,
        )

    # 3. Verify external checkpoint chain integrity & signatures
    errors: list[str] = []
    expected_cp_seq = 1
    expected_prev_cp_hash = GENESIS_CHECKPOINT_HASH
    prev_head_seq = 0
    divergence: DivergenceType | None = None

    ring: KeyRing
    if isinstance(key_ring, bytes):
        record = create_key_record(key_ring)
        ring = KeyRing([record])
    else:
        ring = key_ring

    for cp in checkpoints:
        if cp.checkpoint_seq != expected_cp_seq:
            errors.append(
                f"Checkpoint {cp.checkpoint_id}: sequence mismatch "
                f"(expected {expected_cp_seq}, got {cp.checkpoint_seq})"
            )
            divergence = divergence or "CHECKPOINT_TAMPERING"

        if cp.prev_checkpoint_hash != expected_prev_cp_hash:
            errors.append(
                f"Checkpoint {cp.checkpoint_id} (seq {cp.checkpoint_seq}): "
                f"prev_checkpoint_hash mismatch "
                f"(expected {expected_prev_cp_hash}, got {cp.prev_checkpoint_hash})"
            )
            divergence = divergence or "CHECKPOINT_TAMPERING"

        if cp.head_seq < prev_head_seq:
            errors.append(
                f"Checkpoint {cp.checkpoint_id} (seq {cp.checkpoint_seq}): head_seq decreased "
                f"(previous {prev_head_seq}, current {cp.head_seq})"
            )
            divergence = divergence or "CHECKPOINT_TAMPERING"

        k_rec = ring.get_key(cp.key_id)
        if k_rec is None:
            errors.append(
                f"Checkpoint {cp.checkpoint_id} signed by untrusted/unknown key '{cp.key_id}'"
            )
            divergence = divergence or "UNTRUSTED_KEY"
        else:
            ok_key, key_err = ring.validate_key_at_time(cp.key_id, cp.created_at)
            if not ok_key:
                errors.append(
                    f"Checkpoint {cp.checkpoint_id} key validation failed: {key_err}"
                )
                if "revoked" in key_err.lower():
                    divergence = divergence or "REVOKED_KEY"
                elif "expired" in key_err.lower():
                    divergence = divergence or "KEY_EXPIRED"
                else:
                    divergence = divergence or "UNTRUSTED_KEY"

        ok_sig, sig_err = verify_checkpoint(cp, ring)
        if not ok_sig:
            errors.append(f"Checkpoint {cp.checkpoint_id} signature failed: {sig_err}")
            divergence = divergence or "SIGNATURE_FORGERY"

        expected_prev_cp_hash = cp.compute_checkpoint_hash()
        expected_cp_seq += 1
        prev_head_seq = cp.head_seq

    if errors:
        return AuditTrailVerificationResult(
            ok=False,
            receipts_verified=vr.total_records,
            checkpoints_verified=len(checkpoints),
            head_seq=vr.total_records,
            head_hash=vr.last_hash,
            latest_checkpoint_seq=checkpoints[-1].checkpoint_seq if checkpoints else 0,
            divergence_type=divergence,
            errors=tuple(errors),
        )

    # 4. Cross-verify SQLite receipts against all external checkpoints
    store = ReceiptStore(db_path)
    records = store.iter_records()
    total_local = len(records)

    latest_cp = checkpoints[-1]
    if total_local < latest_cp.head_seq:
        errors.append(
            f"Historical rollback/tail truncation detected: external checkpoint "
            f"#{latest_cp.checkpoint_seq} anchors head_seq={latest_cp.head_seq}, "
            f"but local SQLite only contains {total_local} records."
        )
        divergence = "ROLLBACK"

    for cp in checkpoints:
        if cp.head_seq == 0:
            continue
        if cp.head_seq <= total_local:
            rec = records[cp.head_seq - 1]
            if rec.seq != cp.head_seq or rec.entry_hash != cp.head_hash:
                errors.append(
                    f"Audit log rewrite/fork detected at seq={cp.head_seq}: "
                    f"external checkpoint #{cp.checkpoint_seq} anchors hash '{cp.head_hash}', "
                    f"but local SQLite has entry_hash '{rec.entry_hash}'."
                )
                divergence = "CHAIN_REWRITE"

    return AuditTrailVerificationResult(
        ok=len(errors) == 0,
        receipts_verified=total_local,
        checkpoints_verified=len(checkpoints),
        head_seq=total_local,
        head_hash=vr.last_hash,
        latest_checkpoint_seq=latest_cp.checkpoint_seq,
        divergence_type=divergence if errors else None,
        errors=tuple(errors),
        details={
            "anchored_head_seq": latest_cp.head_seq,
            "anchored_head_hash": latest_cp.head_hash,
            "total_local_receipts": total_local,
            "latest_checkpoint_id": latest_cp.checkpoint_id,
        },
    )


# -----------------------------------------------------------------------------
# 7. Offline Audit Bundle Verifier
# -----------------------------------------------------------------------------


def verify_audit_bundle(
    bundle_path_or_dict: str | Path | dict[str, Any],
) -> AuditTrailVerificationResult:
    """Independently verify an exported audit bundle completely offline."""
    bundle: dict[str, Any]
    if isinstance(bundle_path_or_dict, (str, Path)):
        try:
            bundle = json.loads(Path(bundle_path_or_dict).read_text(encoding="utf-8"))
        except Exception as exc:
            return AuditTrailVerificationResult(
                ok=False,
                receipts_verified=0,
                checkpoints_verified=0,
                head_seq=0,
                head_hash=GENESIS_HASH,
                latest_checkpoint_seq=0,
                divergence_type="RECEIPT_TAMPERING",
                errors=(f"Unable to read audit bundle: {exc}",),
            )
    else:
        bundle = bundle_path_or_dict

    raw_keys = bundle.get("key_manifest", {})
    key_ring = KeyRing.from_dict(raw_keys) if raw_keys else KeyRing([])

    raw_receipts = bundle.get("receipts", [])
    errors: list[str] = []
    expected_seq = 1
    expected_prev = GENESIS_HASH
    last_hash = GENESIS_HASH

    from actentra_core.receipts import _compute_entry_hash

    for r in raw_receipts:
        seq = int(r["seq"])
        if seq != expected_seq:
            errors.append(f"seq {seq}: expected sequence number {expected_seq}")
        if str(r["prev_hash"]) != expected_prev:
            errors.append(
                f"seq {seq}: prev_hash mismatch (expected {expected_prev}, got {r['prev_hash']})"
            )
        computed = _compute_entry_hash(
            seq=seq,
            record_type=str(r["record_type"]),
            crossing_id=str(r["crossing_id"]),
            session_id=str(r["session_id"]),
            canonical_hash=str(r["canonical_hash"]),
            policy_version=str(r["policy_version"]),
            verdict=r.get("verdict"),
            rule_id=r.get("rule_id"),
            reason=r.get("reason"),
            risk_tags=tuple(r.get("risk_tags", ())),
            shadow=bool(r.get("shadow", False)),
            status=r.get("status"),
            result_hash=r.get("result_hash"),
            error=r.get("error"),
            ts=str(r["ts"]),
            prev_hash=str(r["prev_hash"]),
            evidence_status=r.get("evidence_status"),
        )
        if computed != str(r["entry_hash"]):
            errors.append(
                f"seq {seq}: entry_hash mismatch (computed {computed}, stored {r['entry_hash']})"
            )
        expected_prev = str(r["entry_hash"])
        last_hash = str(r["entry_hash"])
        expected_seq += 1

    if errors:
        return AuditTrailVerificationResult(
            ok=False,
            receipts_verified=len(raw_receipts),
            checkpoints_verified=0,
            head_seq=len(raw_receipts),
            head_hash=last_hash,
            latest_checkpoint_seq=0,
            divergence_type="RECEIPT_TAMPERING",
            errors=tuple(errors),
        )

    raw_cps = bundle.get("external_checkpoints", [])
    if not raw_cps:
        return AuditTrailVerificationResult(
            ok=True,
            receipts_verified=len(raw_receipts),
            checkpoints_verified=0,
            head_seq=len(raw_receipts),
            head_hash=last_hash,
            latest_checkpoint_seq=0,
        )

    checkpoints = [SignedCheckpoint.from_dict(c) for c in raw_cps]
    anchor = MemoryCheckpointAnchor()
    for cp in checkpoints:
        anchor.save_checkpoint(cp)

    expected_prev_cp = GENESIS_CHECKPOINT_HASH
    divergence: DivergenceType | None = None
    for cp in checkpoints:
        if cp.prev_checkpoint_hash != expected_prev_cp:
            errors.append(f"Checkpoint #{cp.checkpoint_seq}: prev_checkpoint_hash mismatch")
            divergence = divergence or "CHECKPOINT_TAMPERING"
        ok_sig, sig_err = verify_checkpoint(cp, key_ring)
        if not ok_sig:
            errors.append(
                f"Checkpoint #{cp.checkpoint_seq} signature verification failed: {sig_err}"
            )
            divergence = divergence or "SIGNATURE_FORGERY"
        expected_prev_cp = cp.compute_checkpoint_hash()

    latest_cp = checkpoints[-1]
    if len(raw_receipts) < latest_cp.head_seq:
        errors.append(
            f"Bundle receipts truncated: has {len(raw_receipts)}, "
            f"checkpoint requires {latest_cp.head_seq}"
        )
        divergence = "ROLLBACK"

    for cp in checkpoints:
        if cp.head_seq > 0 and cp.head_seq <= len(raw_receipts):
            r = raw_receipts[cp.head_seq - 1]
            if r["entry_hash"] != cp.head_hash:
                errors.append(
                    f"Audit rewrite detected at seq={cp.head_seq}: "
                    f"checkpoint head is {cp.head_hash}, bundle receipt is {r['entry_hash']}"
                )
                divergence = "CHAIN_REWRITE"

    return AuditTrailVerificationResult(
        ok=len(errors) == 0,
        receipts_verified=len(raw_receipts),
        checkpoints_verified=len(checkpoints),
        head_seq=len(raw_receipts),
        head_hash=last_hash,
        latest_checkpoint_seq=latest_cp.checkpoint_seq,
        divergence_type=divergence if errors else None,
        errors=tuple(errors),
    )
