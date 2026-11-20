"""Cryptographic Warrants (Capability Tokens) for Actentra.

A Warrant is a signed, scoped, expiring authorization token delegating temporary,
least-privilege authority to an agent or subagent without granting ambient credentials.
Implements Phase 4 delegation capabilities.
"""

from __future__ import annotations

import base64
import contextlib
import fnmatch
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from actentra_core.canonicalize import (
    CanonicalizationError,
    canonicalize_json,
    match_resource_pattern,
)
from actentra_core.envelope import generate_crossing_id


class WarrantError(Exception):
    """Raised when warrant generation, verification, or consumption fails."""


@dataclass(frozen=True, slots=True)
class Warrant:
    """Immutable signed capability token delegating scoped tool and resource authority."""

    warrant_id: str
    issuer: str
    holder: str
    allowed_tools: tuple[str, ...]
    allowed_resources: tuple[str, ...]
    max_uses: int | None
    issued_at: str
    expires_at: str
    signature: str

    def payload_bytes(self) -> bytes:
        """Deterministic canonical representation over which the Ed25519 signature is computed."""
        data = {
            "warrant_id": self.warrant_id,
            "issuer": self.issuer,
            "holder": self.holder,
            "allowed_tools": list(self.allowed_tools),
            "allowed_resources": list(self.allowed_resources),
            "max_uses": self.max_uses,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        return canonicalize_json(data).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {
            "warrant_id": self.warrant_id,
            "issuer": self.issuer,
            "holder": self.holder,
            "allowed_tools": list(self.allowed_tools),
            "allowed_resources": list(self.allowed_resources),
            "max_uses": self.max_uses,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Warrant:
        return cls(
            warrant_id=str(data["warrant_id"]),
            issuer=str(data["issuer"]),
            holder=str(data["holder"]),
            allowed_tools=tuple(str(t) for t in data.get("allowed_tools", ())),
            allowed_resources=tuple(str(r) for r in data.get("allowed_resources", ())),
            max_uses=int(data["max_uses"]) if data.get("max_uses") is not None else None,
            issued_at=str(data["issued_at"]),
            expires_at=str(data["expires_at"]),
            signature=str(data["signature"]),
        )


def issue_warrant(
    *,
    holder: str,
    allowed_tools: list[str] | tuple[str, ...],
    allowed_resources: list[str] | tuple[str, ...],
    privkey_pem: bytes,
    issuer_id: str,
    ttl_seconds: float = 3600.0,
    max_uses: int | None = None,
    receipt_store: Any | None = None,
) -> Warrant:
    """Issue and sign an Ed25519 capability warrant for a specific agent holder."""
    now = datetime.now(UTC)
    now_ts = now.timestamp()
    exp_dt = datetime.fromtimestamp(now_ts + ttl_seconds, tz=UTC)

    issued_at = now.isoformat().replace("+00:00", "Z")
    expires_at = exp_dt.isoformat().replace("+00:00", "Z")
    warrant_id = f"war_{generate_crossing_id()}"

    unsigned = Warrant(
        warrant_id=warrant_id,
        issuer=issuer_id,
        holder=holder,
        allowed_tools=tuple(allowed_tools),
        allowed_resources=tuple(allowed_resources),
        max_uses=max_uses,
        issued_at=issued_at,
        expires_at=expires_at,
        signature="",
    )

    try:
        loaded_key = load_pem_private_key(privkey_pem, password=None)
    except Exception as exc:
        raise WarrantError(f"Failed to load Ed25519 private key: {exc}") from exc

    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise WarrantError("Private key must be Ed25519")

    sig_bytes = loaded_key.sign(unsigned.payload_bytes())
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    signed = Warrant(
        warrant_id=unsigned.warrant_id,
        issuer=unsigned.issuer,
        holder=unsigned.holder,
        allowed_tools=unsigned.allowed_tools,
        allowed_resources=unsigned.allowed_resources,
        max_uses=unsigned.max_uses,
        issued_at=unsigned.issued_at,
        expires_at=unsigned.expires_at,
        signature=sig_b64,
    )

    if receipt_store is not None:
        receipt_store.record_warrant_issuance(signed)

    return signed


def verify_warrant(
    warrant: Warrant,
    pubkey_pem: bytes,
    *,
    expected_holder: str | None = None,
    current_time_iso: str | None = None,
) -> tuple[bool, str]:
    """Verify cryptographic signature and expiration of a Warrant."""
    try:
        loaded_pub = load_pem_public_key(pubkey_pem)
    except Exception as exc:
        return False, f"Failed to load Ed25519 public key: {exc}"

    if not isinstance(loaded_pub, Ed25519PublicKey):
        return False, "Public key must be Ed25519"

    try:
        sig_bytes = base64.b64decode(warrant.signature)
        loaded_pub.verify(sig_bytes, warrant.payload_bytes())
    except (InvalidSignature, ValueError) as exc:
        return False, f"Cryptographic signature invalid: {exc}"

    # Check holder constraint if specified
    if expected_holder is not None and warrant.holder != expected_holder:
        return (
            False,
            f"Warrant holder mismatch (expected '{expected_holder}', got '{warrant.holder}')",
        )

    # Check expiration
    now_dt = datetime.now(UTC)
    if current_time_iso:
        with contextlib.suppress(ValueError):
            now_dt = datetime.fromisoformat(current_time_iso.replace("Z", "+00:00"))

    try:
        exp_dt = datetime.fromisoformat(warrant.expires_at.replace("Z", "+00:00"))
        if now_dt >= exp_dt:
            return False, f"Warrant expired at {warrant.expires_at}"
    except ValueError as exc:
        return False, f"Malformed expiration date: {exc}"

    return True, "Warrant valid"


def is_action_permitted_by_warrant(warrant: Warrant, tool: str, resource: str) -> bool:
    """Check if a specific tool and resource are authorized by a warrant."""
    tool_clean = tool.strip().lower()
    tool_allowed = False
    for pat in warrant.allowed_tools:
        if fnmatch.fnmatchcase(tool_clean, pat.lower()):
            tool_allowed = True
            break
    if not tool_allowed:
        return False

    res_allowed = False
    for pat in warrant.allowed_resources:
        try:
            if match_resource_pattern(pat, resource):
                res_allowed = True
                break
        except CanonicalizationError:
            continue
    return res_allowed


class WarrantRegistry:
    """Thread-safe, durable tracker of consumed uses for scoped capability warrants.

    Supports durable SQLite persistence (via ReceiptStore or direct db_path)
    to enforce quota durability across process restarts and prevent eviction attacks.
    """

    def __init__(
        self,
        max_warrants: int = 1000,
        *,
        receipt_store: Any | None = None,
        db_path: str | Path | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._max_warrants = max_warrants
        self._receipt_store = receipt_store
        self._db_path = Path(db_path) if db_path is not None else None
        self._uses: dict[str, int] = {}
        self._limits: dict[str, int | None] = {}

        if self._db_path is not None and self._receipt_store is None:
            from actentra_core.receipts import ReceiptStore

            self._receipt_store = ReceiptStore(self._db_path)

    @property
    def receipt_store(self) -> Any | None:
        return self._receipt_store

    def set_receipt_store(self, store: Any | None) -> None:
        """Attach receipt store for durable warrant persistence across restarts."""
        with self._lock:
            self._receipt_store = store

    def record_use(self, warrant: Warrant) -> None:
        """Increment consumed uses for a warrant; raises WarrantError if exceeded."""
        with self._lock:
            if self._receipt_store is not None:
                self._receipt_store.record_warrant_use(warrant)
                self._uses[warrant.warrant_id] = self._uses.get(warrant.warrant_id, 0) + 1
                self._limits[warrant.warrant_id] = warrant.max_uses
                return

            # In-memory fallback
            current = self._uses.get(warrant.warrant_id, 0)
            if warrant.max_uses is not None and current >= warrant.max_uses:
                raise WarrantError(
                    f"Warrant '{warrant.warrant_id}' max uses ({warrant.max_uses}) exceeded"
                )

            # Never evict active exhausted warrants whose quota must be enforced
            if len(self._uses) >= self._max_warrants and warrant.warrant_id not in self._uses:
                evict_candidate = None
                for wid, limit in self._limits.items():
                    if limit is None:  # unlimited warrant uses can safely be evicted
                        evict_candidate = wid
                        break
                if evict_candidate is not None:
                    del self._uses[evict_candidate]
                    del self._limits[evict_candidate]
                elif len(self._uses) >= self._max_warrants * 2:
                    # Emergency unbounded cap only if purely in-memory
                    oldest = next(iter(self._uses))
                    del self._uses[oldest]
                    self._limits.pop(oldest, None)

            self._uses[warrant.warrant_id] = current + 1
            self._limits[warrant.warrant_id] = warrant.max_uses

    def remaining_uses(self, warrant: Warrant) -> int | None:
        """Return remaining allowed uses, or None if unlimited."""
        if warrant.max_uses is None:
            return None
        with self._lock:
            if self._receipt_store is not None:
                return cast(int | None, self._receipt_store.get_warrant_remaining_uses(warrant))
            current = self._uses.get(warrant.warrant_id, 0)
            return max(0, warrant.max_uses - current)
