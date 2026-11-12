"""Local-first Secrets Broker v1 for Actentra (Windows DPAPI + redaction, Invariant I7).

Agents never receive raw credentials in ActionEnvelopes, receipts, or error messages.
Secrets are encrypted at rest with the current Windows user's DPAPI key when persisted
via ``DPAPISecretsStore`` and injected only at execution time.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path


class SecretsError(RuntimeError):
    """Raised when a secret cannot be retrieved, protected, or stored."""


if sys.platform == "win32":

    class _DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]


def dpapi_protect(plaintext: bytes, *, entropy: bytes | None = None) -> bytes:
    """Encrypt bytes using Windows DPAPI (CurrentUser scope)."""
    if sys.platform != "win32":
        raise SecretsError("Windows DPAPI is only supported on Windows")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_buf = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    in_blob = _DataBlob(len(plaintext), in_buf)
    out_blob = _DataBlob()

    ent_blob_ptr = None
    if entropy:
        ent_buf = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
        ent_blob = _DataBlob(len(entropy), ent_buf)
        ent_blob_ptr = ctypes.byref(ent_blob)

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "ActentraSecret",
        ent_blob_ptr,
        None,
        None,
        0x01,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SecretsError(f"DPAPI CryptProtectData failed (winerr={ctypes.GetLastError()})")

    try:
        return bytes(ctypes.string_at(out_blob.pbData, out_blob.cbData))
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_unprotect(ciphertext: bytes, *, entropy: bytes | None = None) -> bytes:
    """Decrypt Windows DPAPI-protected bytes (CurrentUser scope)."""
    if sys.platform != "win32":
        raise SecretsError("Windows DPAPI is only supported on Windows")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_buf = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
    in_blob = _DataBlob(len(ciphertext), in_buf)
    out_blob = _DataBlob()

    ent_blob_ptr = None
    if entropy:
        ent_buf = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy)
        ent_blob = _DataBlob(len(entropy), ent_buf)
        ent_blob_ptr = ctypes.byref(ent_blob)

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ent_blob_ptr,
        None,
        None,
        0x01,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SecretsError(f"DPAPI CryptUnprotectData failed (winerr={ctypes.GetLastError()})")

    try:
        return bytes(ctypes.string_at(out_blob.pbData, out_blob.cbData))
    finally:
        kernel32.LocalFree(out_blob.pbData)


class SecretsBroker:
    """Holds credentials outside the agent context and redacts leaks (Invariant I7)."""

    def __init__(
        self,
        initial: dict[str, str] | None = None,
        *,
        env_prefix: str | None = None,
        dpapi_store_path: str | Path | None = None,
    ) -> None:
        self._secrets: dict[str, str] = {}
        self._env_prefix = env_prefix
        self._dpapi_path = Path(dpapi_store_path) if dpapi_store_path is not None else None

        if self._dpapi_path is not None and self._dpapi_path.exists():
            self._load_dpapi_file()
        if initial:
            for k, v in initial.items():
                self._secrets[k] = v

    def _load_dpapi_file(self) -> None:
        assert self._dpapi_path is not None
        try:
            raw = json.loads(self._dpapi_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SecretsError(f"Unable to read DPAPI secrets store: {exc}") from exc
        if not isinstance(raw, dict):
            raise SecretsError("DPAPI secrets file root must be an object")
        for name, b64_val in raw.items():
            if not isinstance(name, str) or not isinstance(b64_val, str):
                raise SecretsError("Invalid entry in DPAPI secrets file")
            decrypted = dpapi_unprotect(base64.b64decode(b64_val.encode("ascii")))
            self._secrets[name] = decrypted.decode("utf-8")

    def _save_dpapi_file(self) -> None:
        assert self._dpapi_path is not None
        self._dpapi_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            name: base64.b64encode(dpapi_protect(val.encode("utf-8"))).decode("ascii")
            for name, val in sorted(self._secrets.items())
        }
        self._dpapi_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def set_secret(self, name: str, value: str, *, persist: bool = True) -> None:
        """Store a named secret (and persist encrypted with DPAPI if configured)."""
        if not name or not value:
            raise SecretsError("Secret name and value must be non-empty")
        self._secrets[name] = value
        if persist and self._dpapi_path is not None:
            self._save_dpapi_file()

    def get_secret(self, name: str) -> str:
        """Retrieve a secret for executor injection (never expose to agent/envelopes)."""
        if name in self._secrets:
            return self._secrets[name]
        if self._env_prefix is not None:
            env_val = os.environ.get(f"{self._env_prefix}{name}")
            if env_val:
                self._secrets[name] = env_val
                return env_val
        raise SecretsError(f"Secret not found: {name!r}")

    def list_names(self) -> tuple[str, ...]:
        """Return secret identifiers only (never values)."""
        return tuple(sorted(self._secrets.keys()))

    def redact(self, text: str) -> str:
        """Scrub any known secret values from logs or error messages."""
        redacted = text
        # Replace longest secrets first to avoid partial prefix leakage.
        for val in sorted(self._secrets.values(), key=len, reverse=True):
            if val and val in redacted:
                redacted = redacted.replace(val, "[REDACTED]")
        return redacted
