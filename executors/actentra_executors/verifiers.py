"""Read-only verifiable state observers for Actentra (Phase 2)."""

from __future__ import annotations

import contextlib
import hashlib
import os
import time
from pathlib import Path
from typing import Literal

from actentra_core.canonicalize import (
    CanonicalizationError,
    canonicalize_windows_path,
)
from actentra_core.observations import (
    ObservationError,
    ObservationRecord,
    build_observation,
    utc_iso,
)

_VERIFIER_ID = "actentra.verifier.fs.v1"
_VERIFIER_VERSION = "1.0.0"
_TRUST_DOMAIN: Literal["local_host", "remote_service", "external_witness"] = "local_host"
_DEFAULT_FRESHNESS_TTL = 60.0  # 60 seconds
_MAX_DIGEST_READ_BYTES = 50 * 1024 * 1024  # 50 MiB cap for digest hashing


class WorkspaceFileVerifier:
    """Read-only state verifier confined strictly to workspace_root."""

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        default_ttl_seconds: float = _DEFAULT_FRESHNESS_TTL,
    ) -> None:
        raw_root = str(Path(workspace_root).resolve())
        self._workspace_root = canonicalize_windows_path(raw_root, resolve_fs=True)
        self._root_path = Path(
            self._workspace_root.replace("/", "\\") if os.name == "nt" else self._workspace_root
        )
        self._default_ttl = default_ttl_seconds

    @property
    def workspace_root(self) -> str:
        return self._workspace_root

    def _resolve_target(self, resource: str) -> tuple[Path, str]:
        clean = resource.strip()
        if not clean.startswith("path:"):
            raise ObservationError(
                f"Unsupported resource scheme for workspace verifier: {resource!r}"
            )
        raw_path = clean[5:]
        try:
            canon = canonicalize_windows_path(
                raw_path,
                base_dir=self._workspace_root,
                resolve_fs=True,
            )
        except CanonicalizationError as exc:
            raise ObservationError(f"Path outside workspace or malformed: {exc}") from exc

        target = Path(canon.replace("/", "\\") if os.name == "nt" else canon)
        try:
            target.relative_to(self._root_path)
        except ValueError as exc:
            raise ObservationError(
                f"Path {raw_path!r} resolved outside workspace root {self._workspace_root}"
            ) from exc
        return target, f"path:{canon}"

    def _compute_file_digest(self, path: Path) -> tuple[str, int]:
        h = hashlib.sha256()
        total_read = 0
        with path.open("rb") as fh:
            while chunk := fh.read(65536):
                total_read += len(chunk)
                if total_read > _MAX_DIGEST_READ_BYTES:
                    raise ObservationError(
                        f"File size exceeds max digest scan cap ({_MAX_DIGEST_READ_BYTES} bytes)"
                    )
                h.update(chunk)
        return f"sha256:{h.hexdigest()}", total_read

    def verify(
        self,
        resource: str,
        claim: str,
        *,
        crossing_id: str | None = None,
        expected_digest: str | None = None,
        ttl_seconds: float | None = None,
        now: float | None = None,
    ) -> ObservationRecord:
        """Inspect the current workspace state and return an ObservationRecord."""
        norm_claim = claim.strip().lower()
        curr_time = now if now is not None else time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        obs_time = utc_iso(curr_time)
        exp_time = utc_iso(curr_time + ttl)

        try:
            target, norm_res = self._resolve_target(resource)
        except Exception as exc:
            return build_observation(
                subject_resource=resource.strip(),
                claim=norm_claim,
                status="error",
                verifier_id=_VERIFIER_ID,
                verifier_version=_VERIFIER_VERSION,
                trust_domain=_TRUST_DOMAIN,
                crossing_id=crossing_id,
                observed_at=obs_time,
                expires_at=exp_time,
                error=f"Target resolution error: {exc}",
                metadata={"resolved": False},
            )

        # 1. Claim: exists
        if norm_claim == "exists":
            if target.exists() and target.is_file():
                try:
                    digest, size = self._compute_file_digest(target)
                    return build_observation(
                        subject_resource=norm_res,
                        claim=norm_claim,
                        status="verified",
                        verifier_id=_VERIFIER_ID,
                        verifier_version=_VERIFIER_VERSION,
                        trust_domain=_TRUST_DOMAIN,
                        observed_digest=digest,
                        crossing_id=crossing_id,
                        observed_at=obs_time,
                        expires_at=exp_time,
                        metadata={"exists": True, "size_bytes": size, "is_file": True},
                    )
                except Exception as exc:
                    return build_observation(
                        subject_resource=norm_res,
                        claim=norm_claim,
                        status="error",
                        verifier_id=_VERIFIER_ID,
                        verifier_version=_VERIFIER_VERSION,
                        trust_domain=_TRUST_DOMAIN,
                        crossing_id=crossing_id,
                        observed_at=obs_time,
                        expires_at=exp_time,
                        error=f"Read error: {exc}",
                        metadata={"exists": True},
                    )
            elif target.exists() and target.is_dir():
                return build_observation(
                    subject_resource=norm_res,
                    claim=norm_claim,
                    status="refuted",
                    verifier_id=_VERIFIER_ID,
                    verifier_version=_VERIFIER_VERSION,
                    trust_domain=_TRUST_DOMAIN,
                    crossing_id=crossing_id,
                    observed_at=obs_time,
                    expires_at=exp_time,
                    metadata={"exists": True, "is_dir": True, "is_file": False},
                    error="Target is a directory, not a file",
                )
            else:
                return build_observation(
                    subject_resource=norm_res,
                    claim=norm_claim,
                    status="refuted",
                    verifier_id=_VERIFIER_ID,
                    verifier_version=_VERIFIER_VERSION,
                    trust_domain=_TRUST_DOMAIN,
                    crossing_id=crossing_id,
                    observed_at=obs_time,
                    expires_at=exp_time,
                    metadata={"exists": False},
                )

        # 2. Claim: absent
        elif norm_claim == "absent":
            if not target.exists():
                return build_observation(
                    subject_resource=norm_res,
                    claim=norm_claim,
                    status="verified",
                    verifier_id=_VERIFIER_ID,
                    verifier_version=_VERIFIER_VERSION,
                    trust_domain=_TRUST_DOMAIN,
                    crossing_id=crossing_id,
                    observed_at=obs_time,
                    expires_at=exp_time,
                    metadata={"exists": False},
                )
            else:
                digest = None
                size = 0
                if target.is_file():
                    with contextlib.suppress(Exception):
                        digest, size = self._compute_file_digest(target)
                return build_observation(
                    subject_resource=norm_res,
                    claim=norm_claim,
                    status="refuted",
                    verifier_id=_VERIFIER_ID,
                    verifier_version=_VERIFIER_VERSION,
                    trust_domain=_TRUST_DOMAIN,
                    observed_digest=digest,
                    crossing_id=crossing_id,
                    observed_at=obs_time,
                    expires_at=exp_time,
                    metadata={"exists": True, "size_bytes": size},
                )

        # 3. Claim: digest_match
        elif norm_claim == "digest_match":
            if not expected_digest:
                return build_observation(
                    subject_resource=norm_res,
                    claim=norm_claim,
                    status="error",
                    verifier_id=_VERIFIER_ID,
                    verifier_version=_VERIFIER_VERSION,
                    trust_domain=_TRUST_DOMAIN,
                    crossing_id=crossing_id,
                    observed_at=obs_time,
                    expires_at=exp_time,
                    error="expected_digest required for digest_match claim",
                )
            if not target.exists() or not target.is_file():
                return build_observation(
                    subject_resource=norm_res,
                    claim=norm_claim,
                    status="refuted",
                    verifier_id=_VERIFIER_ID,
                    verifier_version=_VERIFIER_VERSION,
                    trust_domain=_TRUST_DOMAIN,
                    crossing_id=crossing_id,
                    observed_at=obs_time,
                    expires_at=exp_time,
                    metadata={
                        "exists": target.exists(),
                        "digest_match": False,
                        "expected_digest": expected_digest,
                    },
                )
            try:
                observed_dig, size = self._compute_file_digest(target)
                matches = observed_dig.lower() == expected_digest.strip().lower()
                return build_observation(
                    subject_resource=norm_res,
                    claim=norm_claim,
                    status="verified" if matches else "refuted",
                    verifier_id=_VERIFIER_ID,
                    verifier_version=_VERIFIER_VERSION,
                    trust_domain=_TRUST_DOMAIN,
                    observed_digest=observed_dig,
                    crossing_id=crossing_id,
                    observed_at=obs_time,
                    expires_at=exp_time,
                    metadata={
                        "digest_match": matches,
                        "expected_digest": expected_digest,
                        "observed_digest": observed_dig,
                        "size_bytes": size,
                    },
                )
            except Exception as exc:
                return build_observation(
                    subject_resource=norm_res,
                    claim=norm_claim,
                    status="error",
                    verifier_id=_VERIFIER_ID,
                    verifier_version=_VERIFIER_VERSION,
                    trust_domain=_TRUST_DOMAIN,
                    crossing_id=crossing_id,
                    observed_at=obs_time,
                    expires_at=exp_time,
                    error=f"Digest error: {exc}",
                )

        else:
            return build_observation(
                subject_resource=norm_res,
                claim=norm_claim,
                status="error",
                verifier_id=_VERIFIER_ID,
                verifier_version=_VERIFIER_VERSION,
                trust_domain=_TRUST_DOMAIN,
                crossing_id=crossing_id,
                observed_at=obs_time,
                expires_at=exp_time,
                error=f"Unsupported claim type: {claim!r}",
            )
