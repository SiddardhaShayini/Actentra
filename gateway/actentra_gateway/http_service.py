"""Lightweight, local-first HTTP service and Unified Operator Console for Actentra.

Provides versioned REST APIs for policy evaluation, persistent human approvals,
execution continuation, canary diff simulations, and an embedded offline Web Console.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import ssl
import threading
import time
from datetime import UTC, datetime
from enum import StrEnum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from actentra.boundary import Boundary
from actentra_core.causal import CycleDetectedError
from actentra_core.handoffs import (
    ExpiredHandoffError,
    HandoffError,
    UnauthorizedAgentHandoffError,
)
from actentra_core.identity import (
    CallerContext,
    CertificateIdentity,
    DelegationRegistry,
    IdentitySecurityError,
    MTLSPrincipalRegistry,
    extract_certificate_identity,
    get_default_delegation_registry,
    resolve_http_caller_context,
)
from actentra_gateway.services import AppServices, ExecutorRegistry

_MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB bound on HTTP request body
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"})


class DeploymentMode(StrEnum):
    LOCAL = "local"
    PRIVATE_NETWORK = "private_network"
    REMOTE = "remote"


def validate_certificate(cert_path: Path) -> x509.Certificate:
    """Validate that certificate exists, can be parsed, and is not expired/not yet valid."""
    if not cert_path.exists():
        raise FileNotFoundError(f"TLS certificate file not found: {cert_path}")
    raw_data = cert_path.read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(raw_data, default_backend())
    except Exception as exc:
        raise ValueError(f"Invalid TLS certificate in {cert_path}: {exc}") from exc

    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        raise ValueError(
            f"TLS certificate in {cert_path} is not yet valid "
            f"(valid from {cert.not_valid_before_utc.isoformat()})"
        )
    if now > cert.not_valid_after_utc:
        raise ValueError(
            f"TLS certificate in {cert_path} has expired on {cert.not_valid_after_utc.isoformat()}"
        )
    return cert


def create_tls_context(
    *,
    certfile: str | Path,
    keyfile: str | Path,
    key_password: str | None = None,
    ca_certs: str | Path | None = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    """Create a hardened TLS context enforcing TLS 1.2+ and secure cipher suites."""
    cert_p = Path(certfile)
    key_p = Path(keyfile)
    if not key_p.exists():
        raise FileNotFoundError(f"TLS private key file not found: {key_p}")
    # Validate certificate validity dates and format
    validate_certificate(cert_p)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Minimum TLS 1.2 enforces modern cryptographic transport
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")

    try:
        ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p), password=key_password)
    except Exception as exc:
        raise ValueError(f"Failed to load TLS certificate or private key: {exc}") from exc

    if ca_certs:
        ca_p = Path(ca_certs)
        if not ca_p.exists():
            raise FileNotFoundError(f"CA certificate file not found: {ca_p}")
        validate_certificate(ca_p)
        ctx.load_verify_locations(cafile=str(ca_p))
        if require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_OPTIONAL
    elif require_client_cert:
        raise ValueError(
            "require_client_cert=True requires ca_certs to be configured "
            "for client certificate verification"
        )
    return ctx


class PendingCrossing:
    """In-memory compatibility view for pending crossings."""

    __slots__ = (
        "crossing_id",
        "session_id",
        "canonical_hash",
        "tool",
        "verb",
        "resource",
        "risk_tags",
        "reason",
        "ts",
        "expires_at",
    )

    def __init__(
        self,
        crossing_id: str,
        session_id: str,
        canonical_hash: str,
        tool: str,
        verb: str,
        resource: str,
        risk_tags: tuple[str, ...],
        reason: str,
        ts: str,
        expires_at: float,
    ) -> None:
        self.crossing_id = crossing_id
        self.session_id = session_id
        self.canonical_hash = canonical_hash
        self.tool = tool
        self.verb = verb
        self.resource = resource
        self.risk_tags = risk_tags
        self.reason = reason
        self.ts = ts
        self.expires_at = expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "session_id": self.session_id,
            "canonical_hash": self.canonical_hash,
            "tool": self.tool,
            "verb": self.verb,
            "resource": self.resource,
            "risk_tags": list(self.risk_tags),
            "reason": self.reason,
            "ts": self.ts,
            "expires_in_seconds": max(0.0, round(self.expires_at - time.time(), 1)),
        }


ROUTE_SCOPE_MATRIX: dict[tuple[str, str], tuple[str, ...]] = {
    # GET routes (read-only authorization matrix)
    ("GET", "/health"): (),
    ("GET", "/ui"): ("console:access", "operator:access", "system:admin"),
    ("GET", "/"): ("console:access", "operator:access", "system:admin"),
    ("GET", "/v1/crossings/pending"): ("approvals:read", "crossings:read"),
    ("GET", "/v1/crossings/*/lifecycle"): ("crossings:read", "approvals:read"),
    ("GET", "/v1/crossings/*/transitions"): ("crossings:read", "approvals:read"),
    ("GET", "/v1/crossings/*"): ("approvals:read", "crossings:read"),
    ("GET", "/v1/receipts"): ("receipts:read",),
    ("GET", "/v1/verify"): ("audit:verify", "receipts:read"),
    ("GET", "/v1/policy"): ("policies:read",),
    ("GET", "/v1/policy/lint"): ("policies:lint", "policies:read"),
    ("GET", "/v1/bundle/export"): ("audit:export",),
    ("GET", "/v1/observations"): ("observations:read",),
    ("GET", "/v1/observations/*"): ("observations:read",),
    ("GET", "/v1/trace/links"): ("trace:read", "receipts:read"),
    ("GET", "/v1/trace/*"): ("trace:read", "receipts:read"),
    ("GET", "/v1/handoffs"): ("handoffs:read",),
    ("GET", "/v1/handoffs/*"): ("handoffs:read",),
    ("GET", "/v1/evidence"): ("evidence:read",),
    ("GET", "/v1/evidence/*"): ("evidence:read",),
    ("GET", "/v1/leases"): ("leases:read",),
    ("GET", "/v1/leases/*"): ("leases:read",),
    ("GET", "/v1/delegations/*"): ("delegations:read",),
    ("GET", "/v1/sessions"): ("sessions:read",),
    ("GET", "/v1/sessions/*"): ("sessions:read",),
    ("GET", "/v1/metrics"): ("system:metrics", "metrics:read", "operator:access"),
    # POST routes (state-mutating action authorization)
    ("POST", "/v1/crossings"): ("crossings:submit", "crossings:propose", "crossings:evaluate"),
    ("POST", "/v1/crossings/*/approve"): ("crossings:approve", "approvals:write"),
    ("POST", "/v1/crossings/*/execute"): ("crossings:execute",),
    ("POST", "/v1/crossings/*/claim"): ("crossings:claim",),
    ("POST", "/v1/crossings/*/outcome"): ("crossings:outcome",),
    ("POST", "/v1/policy/canary"): ("policies:canary", "policies:read"),
    ("POST", "/v1/simulate"): ("crossings:simulate", "crossings:propose"),
    ("POST", "/v1/observations/verify"): ("observations:verify",),
    ("POST", "/v1/trace/links"): ("trace:write",),
    ("POST", "/v1/handoffs"): ("handoffs:create",),
    ("POST", "/v1/handoffs/*/advance"): ("handoffs:advance",),
    ("POST", "/v1/handoffs/*/verify"): ("handoffs:verify",),
    ("POST", "/v1/leases"): ("leases:acquire",),
    ("POST", "/v1/leases/*/release"): ("leases:release",),
    ("POST", "/v1/freeze"): ("system:freeze",),
    ("POST", "/v1/unfreeze"): ("system:unfreeze",),
    ("POST", "/v1/delegations"): ("delegations:create",),
    ("POST", "/v1/sessions"): ("sessions:create",),
    # DELETE routes
    ("DELETE", "/v1/trace/links/*"): ("trace:delete",),
    ("DELETE", "/v1/delegations/*"): ("delegations:revoke",),
    ("DELETE", "/v1/sessions/*"): ("sessions:revoke",),
}


def match_route_scopes(method: str, path: str) -> tuple[str, ...] | None:
    """Resolve required scopes from ROUTE_SCOPE_MATRIX for method and path."""
    clean_method = method.upper()
    clean_path = path.rstrip("/") or "/"

    # 1. Exact match
    if (clean_method, clean_path) in ROUTE_SCOPE_MATRIX:
        return ROUTE_SCOPE_MATRIX[(clean_method, clean_path)]

    # 2. Wildcard pattern matching
    for (m, pattern), scopes in ROUTE_SCOPE_MATRIX.items():
        if m != clean_method:
            continue
        if "*" in pattern:
            prefix, suffix = pattern.split("*", 1)
            if clean_path.startswith(prefix) and clean_path.endswith(suffix):
                middle = clean_path[len(prefix) : len(clean_path) - len(suffix) if suffix else None]
                if "/" not in middle or not suffix:
                    return scopes
    return None


class ActentraHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Actentra REST API and Unified Operator Console."""

    server: ActentraHTTPServer

    def setup(self) -> None:
        super().setup()
        timeout = getattr(self.server, "request_timeout", 30.0)
        if hasattr(self, "connection") and self.connection and timeout:
            with contextlib.suppress(Exception):
                self.connection.settimeout(timeout)

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (
            TimeoutError,
            ssl.SSLError,
            ssl.SSLEOFError,
            ConnectionResetError,
            BrokenPipeError,
        ):
            self.close_connection = True

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default noisy access logs to keep terminal output clean
        pass

    def _authorize_route(self, method: str, path: str) -> tuple[bool, CallerContext | None]:
        """Verify that the caller context has required scopes for this HTTP method and route."""
        try:
            caller_ctx = self._get_caller_context()
        except IdentitySecurityError as exc:
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": str(exc), "code": "unauthorized_principal"},
            )
            return False, None

        required_scopes = match_route_scopes(method, path)
        if required_scopes is None:
            # Route not found in authorization matrix - allow handler to 404
            return True, caller_ctx

        if not required_scopes:
            # Public or open to all authenticated principals
            return True, caller_ctx

        # Trusted operator has all permissions
        if caller_ctx.is_trusted_operator:
            return True, caller_ctx

        # Check if caller has any of the acceptable scopes
        for scope in required_scopes:
            if caller_ctx.has_scope(scope):
                return True, caller_ctx

        if path.endswith("/approve"):
            err_msg = (
                f"Principal '{caller_ctx.principal_id}' is not authorized to resolve approvals "
                f"(lacks required scope: {list(required_scopes)})"
            )
        elif path == "/v1/freeze":
            err_msg = "Only trusted operators may freeze the system"
        elif path == "/v1/unfreeze":
            err_msg = "Only trusted operators may unfreeze the system"
        else:
            err_msg = (
                f"Forbidden: Principal '{caller_ctx.principal_id}' lacks required scope. "
                f"Required one of: {list(required_scopes)}"
            )

        self._send_json(
            HTTPStatus.FORBIDDEN,
            {
                "error": err_msg,
                "code": "insufficient_scope",
                "principal": caller_ctx.principal_id,
                "required_scopes": list(required_scopes),
            },
        )
        return False, caller_ctx

    def _get_effective_client_ip(self) -> str:
        client_addr = getattr(self, "client_address", None)
        remote_ip = (
            client_addr[0] if isinstance(client_addr, tuple) and client_addr else "127.0.0.1"
        )
        server_obj = getattr(self, "server", None)
        raw_proxies: Any = getattr(server_obj, "trusted_proxies", frozenset())
        trusted_proxies = (
            raw_proxies if isinstance(raw_proxies, (set, frozenset, tuple, list)) else frozenset()
        )
        if remote_ip in trusted_proxies and hasattr(self, "headers") and self.headers:
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                hops = [ip.strip() for ip in xff.split(",") if ip.strip()]
                if hops:
                    return hops[-1]
        return remote_ip

    def _extract_tls_client_cert(self) -> CertificateIdentity | None:
        """Extract CertificateIdentity strictly from the authenticated TLS socket."""
        conn = getattr(self, "connection", None)
        if not isinstance(conn, ssl.SSLSocket):
            return None
        der_bytes = conn.getpeercert(binary_form=True)
        if not der_bytes:
            return None
        return extract_certificate_identity(der_bytes)

    def _get_caller_context(self) -> CallerContext:
        headers_dict = (
            {k.lower(): v for k, v in self.headers.items()}
            if hasattr(self, "headers") and self.headers
            else {}
        )
        remote_ip = self._get_effective_client_ip()
        server_obj = getattr(self, "server", None)
        raw_token = getattr(server_obj, "auth_token", None)
        expected_token = raw_token if isinstance(raw_token, str) else None
        raw_principals = getattr(server_obj, "token_principals", None)
        token_principals = raw_principals if isinstance(raw_principals, dict) else None
        raw_cert_reg = getattr(server_obj, "cert_registry", None)
        cert_registry = raw_cert_reg if isinstance(raw_cert_reg, MTLSPrincipalRegistry) else None
        raw_req = getattr(server_obj, "require_client_cert", False)
        require_client_cert = bool(raw_req) if isinstance(raw_req, bool) else False
        raw_mode = getattr(server_obj, "deployment_mode", DeploymentMode.LOCAL)
        enforce_strict = raw_mode in (DeploymentMode.REMOTE, DeploymentMode.PRIVATE_NETWORK)

        delegation_reg = None
        server_services = getattr(server_obj, "services", None)
        if server_services is not None:
            cand = getattr(server_services, "delegation_registry", None)
            if isinstance(cand, DelegationRegistry):
                delegation_reg = cand
        if delegation_reg is None:
            cand = getattr(server_obj, "delegation_registry", None)
            if isinstance(cand, DelegationRegistry):
                delegation_reg = cand
        if delegation_reg is None:
            delegation_reg = get_default_delegation_registry()

        client_cert = self._extract_tls_client_cert()
        return resolve_http_caller_context(
            headers=headers_dict,
            expected_token=expected_token,
            remote_addr=remote_ip,
            token_principals=token_principals,
            delegation_registry=delegation_reg,
            client_cert=client_cert,
            cert_registry=cert_registry,
            require_client_cert=require_client_cert,
            enforce_strict_shared_token=enforce_strict,
        )

    def _validate_host_header(self) -> bool:
        """Validate Host header against allowed hosts and defend against DNS rebinding."""
        protocol = getattr(self, "request_version", "HTTP/1.1")
        host_hdr = self.headers.get("Host") if hasattr(self, "headers") and self.headers else None
        server_obj = getattr(self, "server", None)
        raw_allowed = getattr(server_obj, "allowed_hosts", ())
        allowed = raw_allowed if isinstance(raw_allowed, (tuple, list, set, frozenset)) else ()
        raw_mode = getattr(server_obj, "deployment_mode", DeploymentMode.LOCAL)
        deployment_mode = (
            raw_mode if isinstance(raw_mode, (DeploymentMode, str)) else DeploymentMode.LOCAL
        )

        if (
            protocol == "HTTP/1.1"
            and not host_hdr
            and (deployment_mode != DeploymentMode.LOCAL or allowed)
        ):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "Missing Host header in HTTP/1.1 request",
                    "code": "missing_host_header",
                },
            )
            return False

        if host_hdr:
            clean_host = host_hdr.strip().split(":")[0].strip().lower()

            if allowed:
                allowed_normalized = [h.strip().lower() for h in allowed]
                if clean_host not in allowed_normalized and clean_host not in _LOOPBACK_HOSTS:
                    self._send_json(
                        HTTPStatus.BAD_REQUEST,
                        {
                            "error": f"Invalid Host header: host {clean_host!r} is not allowed",
                            "code": "invalid_host_header",
                        },
                    )
                    return False
            elif deployment_mode == DeploymentMode.LOCAL and (
                clean_host not in _LOOPBACK_HOSTS and clean_host not in ("testserver", "localhost")
            ):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": (
                            f"Invalid Host header: host {clean_host!r} "
                            "is not permitted in local mode"
                        ),
                        "code": "invalid_host_header",
                    },
                )
                return False
        return True

    def _validate_smuggling_headers(self) -> bool:
        """Check for conflicting or malformed Content-Length and Transfer-Encoding headers."""
        if not hasattr(self, "headers") or not self.headers:
            return True
        cl = self.headers.get("Content-Length")
        te = self.headers.get("Transfer-Encoding")

        if cl is not None and te is not None:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "Conflicting Content-Length and Transfer-Encoding headers (RFC 7230)",
                    "code": "invalid_transfer_encoding",
                },
            )
            return False

        if hasattr(self.headers, "get_all"):
            all_cls = self.headers.get_all("Content-Length")
            if all_cls and len(set(c.strip() for c in all_cls)) > 1:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": "Duplicate conflicting Content-Length headers",
                        "code": "invalid_content_length",
                    },
                )
                return False

        if te is not None and te.strip().lower() not in ("chunked", "identity"):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": f"Unsupported or invalid Transfer-Encoding: {te!r}",
                    "code": "invalid_transfer_encoding",
                },
            )
            return False

        return True

    def _validate_client_cert(self) -> bool:
        """Verify peer certificate and principal binding when mTLS is active."""
        server_obj = getattr(self, "server", None)
        raw_req = getattr(server_obj, "require_client_cert", False)
        require_client_cert = bool(raw_req) if isinstance(raw_req, bool) else False
        raw_cert_reg = getattr(server_obj, "cert_registry", None)
        cert_registry = raw_cert_reg if isinstance(raw_cert_reg, MTLSPrincipalRegistry) else None

        # Reject caller-supplied forwarded certificate headers when not backed by TLS
        if hasattr(self, "headers") and self.headers:
            spoof_hdrs = (
                "X-SSL-Client-Cert",
                "X-Forwarded-Client-Cert",
                "X-Client-Cert",
                "X-Actentra-Client-Cert",
            )
            if any(self.headers.get(h) for h in spoof_hdrs):
                conn = getattr(self, "connection", None)
                if not isinstance(conn, ssl.SSLSocket) or not conn.getpeercert(binary_form=True):
                    self._send_json(
                        HTTPStatus.FORBIDDEN,
                        {
                            "error": (
                                "Caller-supplied client certificate headers are not trusted "
                                "without an authenticated mTLS socket"
                            ),
                            "code": "mtls_spoofed_cert_header",
                        },
                    )
                    return False

        if require_client_cert:
            conn = getattr(self, "connection", None)
            if not isinstance(conn, ssl.SSLSocket):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Client certificate required: connection is not TLS",
                        "code": "mtls_certificate_required",
                    },
                )
                return False
            der_bytes = conn.getpeercert(binary_form=True)
            if not der_bytes:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Mutual TLS client certificate required and none was provided",
                        "code": "mtls_certificate_required",
                    },
                )
                return False
            try:
                cert_id = extract_certificate_identity(der_bytes)
                if not cert_id.is_currently_valid():
                    raise IdentitySecurityError(
                        f"Client certificate '{cert_id.sha256_fingerprint}' is expired "
                        "or not yet valid"
                    )
                if cert_registry is not None:
                    cert_registry.resolve_certificate(cert_id)
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "mtls_principal_rejected"},
                )
                return False
        return True

    def _validate_request(self) -> bool:
        """Run all network-layer validations (Host, smuggling, mTLS, max size)."""
        if not self._validate_host_header():
            return False
        if not self._validate_smuggling_headers():
            return False
        if not self._validate_client_cert():
            return False
        cl_hdr = (
            self.headers.get("Content-Length")
            if hasattr(self, "headers") and self.headers
            else None
        )
        if cl_hdr:
            try:
                if int(cl_hdr) > _MAX_BODY_BYTES:
                    self._send_json(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        {
                            "error": f"Request body exceeds {_MAX_BODY_BYTES} bytes limit",
                            "code": "payload_too_large",
                        },
                    )
                    return False
            except ValueError:
                pass
        return True

    def _validate_nonce_and_timestamp(self) -> bool:
        """Validate request timestamp skew and sliding-window replay protection nonce."""
        ts_hdr = (
            self.headers.get("X-Actentra-Timestamp")
            if hasattr(self, "headers") and self.headers
            else None
        )
        if ts_hdr:
            try:
                req_ts = float(ts_hdr)
            except ValueError:
                try:
                    dt = datetime.fromisoformat(ts_hdr.strip())
                    req_ts = dt.timestamp()
                except Exception:
                    self._send_json(
                        HTTPStatus.BAD_REQUEST,
                        {
                            "error": "Invalid X-Actentra-Timestamp header format",
                            "code": "invalid_timestamp",
                        },
                    )
                    return False
            now = time.time()
            if abs(now - req_ts) > 300.0:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": (
                            f"Request timestamp out of bounds "
                            f"(skew {abs(now - req_ts):.1f}s > 300s)"
                        ),
                        "code": "timestamp_skew",
                    },
                )
                return False

        nonce_hdr = (
            self.headers.get("X-Actentra-Nonce")
            if hasattr(self, "headers") and self.headers
            else None
        )
        if nonce_hdr:
            server_obj = getattr(self, "server", None)
            if server_obj and hasattr(server_obj, "check_and_record_nonce"):
                chk_fn = server_obj.check_and_record_nonce
                if callable(chk_fn):
                    chk_res = chk_fn(nonce_hdr.strip())
                    if isinstance(chk_res, bool) and chk_res is False:
                        self._send_json(
                            HTTPStatus.CONFLICT,
                            {
                                "error": "Request replay detected: nonce has already been used",
                                "code": "replay_detected",
                            },
                        )
                        return False
        return True

    def _check_auth(self) -> bool:
        server_obj = getattr(self, "server", None)
        raw_token = getattr(server_obj, "auth_token", None)
        server_token = raw_token if isinstance(raw_token, str) and raw_token.strip() else None
        raw_principals = getattr(server_obj, "token_principals", None)
        token_principals = raw_principals if isinstance(raw_principals, dict) else None
        if not server_token and not token_principals:
            return True
        auth_hdr = (
            self.headers.get("Authorization", "").strip()
            if hasattr(self, "headers") and self.headers
            else ""
        )
        if not auth_hdr.startswith("Bearer "):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Unauthorized: missing or invalid Bearer token", "code": "unauthorized"},
            )
            return False
        token = auth_hdr[len("Bearer ") :].strip()
        if not token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Unauthorized: missing or invalid Bearer token", "code": "unauthorized"},
            )
            return False

        if server_obj and hasattr(server_obj, "is_token_revoked"):
            rev_fn = server_obj.is_token_revoked
            if callable(rev_fn):
                rev_res = rev_fn(token)
                if isinstance(rev_res, bool) and rev_res is True:
                    self._send_json(
                        HTTPStatus.UNAUTHORIZED,
                        {
                            "error": "Unauthorized: Bearer token has been revoked",
                            "code": "token_revoked",
                        },
                    )
                    return False

        token_valid = False
        if server_token and hmac.compare_digest(token, server_token):
            token_valid = True
        elif token_principals:
            for cand_token, pdata in token_principals.items():
                if hmac.compare_digest(token, str(cand_token)):
                    if isinstance(pdata, dict):
                        if pdata.get("revoked", False):
                            self._send_json(
                                HTTPStatus.UNAUTHORIZED,
                                {
                                    "error": "Unauthorized: Bearer token has been revoked",
                                    "code": "token_revoked",
                                },
                            )
                            return False
                        exp = pdata.get("expires_at")
                        if exp is not None:
                            try:
                                exp_ts = float(exp)
                                if time.time() > exp_ts:
                                    self._send_json(
                                        HTTPStatus.UNAUTHORIZED,
                                        {
                                            "error": "Unauthorized: Bearer token has expired",
                                            "code": "token_expired",
                                        },
                                    )
                                    return False
                            except (ValueError, TypeError):
                                pass
                    token_valid = True
                    break

        if token_valid:
            # Enforce transport-to-application binding when mTLS cert or registry is active
            if self._extract_tls_client_cert() is not None or isinstance(
                getattr(server_obj, "cert_registry", None), MTLSPrincipalRegistry
            ):
                try:
                    self._get_caller_context()
                except IdentitySecurityError as exc:
                    self._send_json(
                        HTTPStatus.FORBIDDEN,
                        {"error": str(exc), "code": "mtls_identity_mismatch"},
                    )
                    return False
            return True

        self._send_json(
            HTTPStatus.UNAUTHORIZED,
            {"error": "Unauthorized: missing or invalid Bearer token", "code": "unauthorized"},
        )
        return False

    def _allowed_origin(self) -> str | None:
        origin = self.headers.get("Origin") if hasattr(self, "headers") and self.headers else None
        if not origin:
            return None
        clean = origin.strip().lower()
        if (
            clean.startswith("http://127.0.0.1:")
            or clean.startswith("http://localhost:")
            or clean in ("http://127.0.0.1", "http://localhost")
            or clean.startswith("https://127.0.0.1:")
            or clean.startswith("https://localhost:")
            or clean in ("https://127.0.0.1", "https://localhost")
        ):
            return origin

        server_obj = getattr(self, "server", None)
        allowed = getattr(server_obj, "allowed_hosts", ())
        if allowed:
            for host in allowed:
                h_clean = host.strip().lower()
                if clean == f"https://{h_clean}" or clean.startswith(f"https://{h_clean}:"):
                    return origin
        return None

    def _send_json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        allowed_origin = self._allowed_origin()
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Actentra-Client, "
            "X-Actentra-Timestamp, X-Actentra-Nonce",
        )
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html_text: str) -> None:
        body = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _send_forbidden(self, error: str, code: str = "unauthorized_principal") -> None:
        self._send_json(HTTPStatus.FORBIDDEN, {"error": error, "code": code})

    def _handle_body_error(self, exc: Exception) -> None:
        if "exceeds" in str(exc):
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": str(exc), "code": "payload_too_large"},
            )
        else:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": f"Invalid body: {exc}", "code": "invalid_body"},
            )

    def _read_json_body(self) -> dict[str, Any]:
        content_len_header = self.headers.get("Content-Length")
        if not content_len_header:
            raise ValueError("Missing Content-Length header")
        try:
            length = int(content_len_header)
        except ValueError as exc:
            raise ValueError(f"Invalid Content-Length header: {content_len_header!r}") from exc
        if length < 0:
            raise ValueError(f"Negative Content-Length header is invalid: {length}")
        if length > _MAX_BODY_BYTES:
            raise ValueError(f"Request body exceeds {_MAX_BODY_BYTES} bytes limit")
        raw_bytes = self.rfile.read(length)
        parsed = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON request body must be an object")
        return parsed

    def do_OPTIONS(self) -> None:
        if not self._validate_request():
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        allowed_origin = self._allowed_origin()
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Actentra-Client, "
            "X-Actentra-Timestamp, X-Actentra-Nonce",
        )
        self.end_headers()

    def do_GET(self) -> None:
        if not self._validate_request():
            return
        if not self._check_auth():
            return

        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query)
        services = self.server.services

        allowed, caller_ctx = self._authorize_route("GET", path)
        if not allowed or caller_ctx is None:
            return

        if path == "/health":
            self._send_json(HTTPStatus.OK, services.get_health())
            return

        if path == "/v1/metrics":
            self._send_json(HTTPStatus.OK, services.get_metrics())
            return

        if path == "/v1/crossings/pending":
            try:
                pending = services.list_pending_approvals(
                    status="pending", caller_context=caller_ctx
                )
                self._send_json(HTTPStatus.OK, pending)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path.startswith("/v1/crossings/") and path.endswith("/lifecycle"):
            cid = path[len("/v1/crossings/") : -len("/lifecycle")]
            try:
                detail = services.get_action_lifecycle(cid, caller_context=caller_ctx)
                if detail is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND,
                        {"error": f"Lifecycle record for crossing '{cid}' not found"},
                    )
                    return
                self._send_json(HTTPStatus.OK, detail)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path.startswith("/v1/crossings/") and path.endswith("/transitions"):
            cid = path[len("/v1/crossings/") : -len("/transitions")]
            try:
                transitions = services.list_action_transitions(cid, caller_context=caller_ctx)
                self._send_json(
                    HTTPStatus.OK,
                    {"crossing_id": cid, "transitions": transitions},
                )
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path.startswith("/v1/crossings/") and not path.endswith(
            ("/approve", "/execute", "/outcome", "/claim", "/lifecycle", "/transitions")
        ):
            cid = path[len("/v1/crossings/") :]
            try:
                detail = services.get_pending_approval(cid, caller_context=caller_ctx)
                if detail is None:
                    detail = services.get_crossing(cid, caller_context=caller_ctx)
                if detail is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Crossing '{cid}' not found"})
                    return
                self._send_json(HTTPStatus.OK, detail)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/receipts":
            query = parse_qs(parts.query)
            try:
                raw_limit = int(query.get("limit", ["50"])[0])
                limit = max(1, min(raw_limit, 500))
            except ValueError:
                limit = 50
            try:
                raw_offset = int(query.get("offset", ["0"])[0])
                offset = max(0, raw_offset)
            except ValueError:
                offset = 0
            verdict = query.get("verdict", [None])[0]
            status_f = query.get("status", [None])[0]
            tool_f = query.get("tool", [None])[0]
            session_f = query.get("session_id", [None])[0]
            search_f = query.get("search", [None])[0]

            try:
                resp = services.query_receipts(
                    limit=limit,
                    offset=offset,
                    verdict=verdict,
                    status=status_f,
                    tool=tool_f,
                    session_id=session_f,
                    search=search_f,
                    caller_context=caller_ctx,
                )
                if "offset" not in query and "search" not in query:
                    self._send_json(HTTPStatus.OK, resp["records"])
                else:
                    self._send_json(HTTPStatus.OK, resp)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/verify":
            try:
                self._send_json(HTTPStatus.OK, services.verify_audit_log(caller_context=caller_ctx))
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/policy":
            try:
                self._send_json(
                    HTTPStatus.OK,
                    {"policy_yaml": services.get_policy_yaml(caller_context=caller_ctx)},
                )
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/policy/lint":
            try:
                self._send_json(
                    HTTPStatus.OK,
                    {"warnings": services.lint_active_policy(caller_context=caller_ctx)},
                )
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/bundle/export":
            try:
                bundle = services.export_audit_bundle(caller_context=caller_ctx)
                self._send_json(HTTPStatus.OK, bundle)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/observations":
            cid_f = query.get("crossing_id", [None])[0]
            res_f = query.get("resource", [None])[0]
            lim_f = int(query.get("limit", [50])[0])
            off_f = int(query.get("offset", [0])[0])
            try:
                obs_list = services.list_observations(
                    crossing_id=cid_f,
                    subject_resource=res_f,
                    limit=lim_f,
                    offset=off_f,
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.OK, obs_list)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path.startswith("/v1/observations/") and path != "/v1/observations/verify":
            obs_id = path[len("/v1/observations/") :]
            try:
                obs_detail = services.get_observation(obs_id, caller_context=caller_ctx)
                if obs_detail is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND, {"error": f"Observation '{obs_id}' not found"}
                    )
                else:
                    self._send_json(HTTPStatus.OK, obs_detail)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/trace/links":
            ent_f = query.get("entity_id", [None])[0]
            lim_f = int(query.get("limit", [100])[0])
            links = services.list_causal_links(entity_id=ent_f, limit=lim_f)
            self._send_json(HTTPStatus.OK, {"items": links, "count": len(links)})
            return

        if path.startswith("/v1/trace/"):
            trace_id = path[len("/v1/trace/") :]
            trace_data = services.get_causal_trace(trace_id)
            self._send_json(HTTPStatus.OK, trace_data)
            return

        if path == "/v1/handoffs":
            task_f = query.get("task_id", [None])[0]
            agent_f = query.get("assigned_agent_id", [None])[0]
            stat_f = query.get("status", [None])[0]
            lim_f = int(query.get("limit", [50])[0])
            try:
                hnds = services.list_task_handoffs(
                    task_id=task_f,
                    assigned_agent_id=agent_f,
                    status=stat_f,
                    limit=lim_f,
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.OK, hnds)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path.startswith("/v1/handoffs/") and not path.endswith(("/advance", "/verify")):
            hnd_id = path[len("/v1/handoffs/") :]
            try:
                hnd = services.get_task_handoff(hnd_id, caller_context=caller_ctx)
                if hnd is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND, {"error": f"Handoff '{hnd_id}' not found"}
                    )
                else:
                    self._send_json(HTTPStatus.OK, hnd)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/evidence":
            query = parse_qs(parts.query)
            cid_f = query.get("crossing_id", [None])[0]
            tier_f = query.get("tier", [None])[0]
            try:
                lim_f = int(query.get("limit", ["50"])[0])
            except ValueError:
                lim_f = 50
            try:
                evs = services.list_evidence(
                    crossing_id=cid_f, tier=tier_f, limit=lim_f, caller_context=caller_ctx
                )
                self._send_json(HTTPStatus.OK, evs)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path.startswith("/v1/evidence/"):
            ev_id = path[len("/v1/evidence/") :]
            try:
                ev = services.get_evidence(ev_id, caller_context=caller_ctx)
                if ev is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND, {"error": f"Evidence '{ev_id}' not found"}
                    )
                else:
                    self._send_json(HTTPStatus.OK, ev)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/leases":
            query = parse_qs(parts.query)
            res_f = query.get("resource", [None])[0]
            agent_f = query.get("owner_agent_id", [None])[0]
            stat_f = query.get("status", [None])[0]
            try:
                lim_f = int(query.get("limit", ["50"])[0])
            except ValueError:
                lim_f = 50
            try:
                leases = services.list_resource_leases(
                    resource=res_f,
                    owner_agent_id=agent_f,
                    status=stat_f,
                    limit=lim_f,
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.OK, leases)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path.startswith("/v1/leases/") and not path.endswith("/release"):
            lid = path[len("/v1/leases/") :]
            try:
                lease = services.get_resource_lease(lid, caller_context=caller_ctx)
                if lease is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Lease '{lid}' not found"})
                else:
                    self._send_json(HTTPStatus.OK, lease)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path == "/v1/sessions":
            pid_f = query.get("principal_id", [None])[0]
            stat_f = query.get("status", [None])[0]
            try:
                lim_f = int(query.get("limit", [50])[0])
            except ValueError:
                lim_f = 50
            try:
                off_f = int(query.get("offset", [0])[0])
            except ValueError:
                off_f = 0
            try:
                sess_list = services.list_sessions(
                    principal_id=pid_f,
                    status=stat_f,
                    limit=lim_f,
                    offset=off_f,
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.OK, sess_list)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path.startswith("/v1/sessions/"):
            sid = path[len("/v1/sessions/") :]
            try:
                sess_detail = services.get_session(sid, caller_context=caller_ctx)
                if sess_detail is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Session '{sid}' not found"})
                else:
                    self._send_json(HTTPStatus.OK, sess_detail)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        if path in ("/ui", "/"):
            self._send_html(HTTPStatus.OK, self._render_dashboard_html())
            return

        if path.startswith("/v1/delegations/"):
            grant_id = path[len("/v1/delegations/") :]
            try:
                grant = services.get_delegation(grant_id, caller_context=caller_ctx)
                if grant is None:
                    self._send_json(
                        HTTPStatus.NOT_FOUND,
                        {"error": f"Delegation grant '{grant_id}' not found"},
                    )
                else:
                    self._send_json(HTTPStatus.OK, grant)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route '{path}' not found"})

    def do_POST(self) -> None:
        if not self._validate_request():
            return
        if not self._validate_nonce_and_timestamp():
            return
        if not self._check_auth():
            return

        parts = urlsplit(self.path)
        path = parts.path.rstrip("/")
        services = self.server.services

        # Mutating requests require loopback origin if Origin is provided
        origin = self.headers.get("Origin")
        if origin and not self._allowed_origin():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Forbidden: cross-origin browser request rejected"},
            )
            return

        allowed, caller_ctx = self._authorize_route("POST", path)
        if not allowed or caller_ctx is None:
            return

        if path == "/v1/crossings":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            raw_execute = data.get("execute", False)
            if not isinstance(raw_execute, bool):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'execute' must be a JSON boolean if provided"},
                )
                return
            execute = raw_execute

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            resp = services.submit_crossing(data, execute=execute, caller_context=caller_ctx)
            if "error" in resp:
                rule_id = str(resp.get("rule_id", ""))
                status_code = (
                    HTTPStatus.FORBIDDEN
                    if rule_id.startswith("identity:")
                    else HTTPStatus.BAD_REQUEST
                )
            else:
                status_code = HTTPStatus.OK
            self._send_json(status_code, resp)
            return

        if path.startswith("/v1/crossings/") and path.endswith("/approve"):
            crossing_id = path[len("/v1/crossings/") : -len("/approve")]
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            if "approved" not in data:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Missing required field 'approved'"},
                )
                return

            approved = data["approved"]
            if not isinstance(approved, bool):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'approved' must be a JSON boolean (true or false)"},
                )
                return

            raw_execute = data.get("execute", False)
            if not isinstance(raw_execute, bool):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'execute' must be a JSON boolean if provided"},
                )
                return
            execute = raw_execute

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            res = services.resolve_approval(
                crossing_id, approved=approved, execute=execute, caller_context=caller_ctx
            )
            if "error" in res:
                err_msg = str(res.get("error", "")).lower()
                status_code = (
                    HTTPStatus.FORBIDDEN
                    if "not authorized" in err_msg or "lacks" in err_msg
                    else HTTPStatus.NOT_FOUND
                )
                self._send_json(status_code, res)
                return
            self._send_json(HTTPStatus.OK, res)
            return

        if path.startswith("/v1/crossings/") and path.endswith("/execute"):
            crossing_id = path[len("/v1/crossings/") : -len("/execute")]
            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            res = services.execute_approved_crossing(crossing_id, caller_context=caller_ctx)
            if "error" in res:
                err_msg = str(res.get("error", "")).lower()
                status_code = (
                    HTTPStatus.FORBIDDEN
                    if "not authorized" in err_msg or "lacks" in err_msg
                    else HTTPStatus.BAD_REQUEST
                )
                self._send_json(status_code, res)
                return
            self._send_json(HTTPStatus.OK, res)
            return

        if path.startswith("/v1/crossings/") and path.endswith("/claim"):
            crossing_id = path[len("/v1/crossings/") : -len("/claim")]
            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            res = services.claim_crossing_for_execution(crossing_id, caller_context=caller_ctx)
            if "error" in res:
                code = res.get("code")
                if code == "forbidden":
                    status_code = HTTPStatus.FORBIDDEN
                elif code == "not_found":
                    status_code = HTTPStatus.NOT_FOUND
                elif (
                    code in ("already_executed", "claim_failed")
                    or "already exists" in str(res.get("error", "")).lower()
                ):
                    status_code = HTTPStatus.CONFLICT
                else:
                    status_code = HTTPStatus.BAD_REQUEST
                self._send_json(status_code, res)
                return
            self._send_json(HTTPStatus.OK, res)
            return

        if path.startswith("/v1/crossings/") and path.endswith("/outcome"):
            crossing_id = path[len("/v1/crossings/") : -len("/outcome")]
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            if "status" not in data:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Missing required field 'status'"},
                )
                return

            status_val = data.get("status")
            if status_val not in ("success", "failure", "unknown"):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'status' must be one of: 'success', 'failure', 'unknown'"},
                )
                return

            claim_id = data.get("claim_id") or self.headers.get("X-Actentra-Claim-Id")
            if not claim_id:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": (
                            "Missing required 'claim_id': external outcome reporting "
                            "requires a valid one-time execution claim issued via "
                            "POST /v1/crossings/{id}/claim"
                        ),
                        "code": "claim_required",
                    },
                )
                return

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            res = services.record_external_outcome(
                crossing_id,
                status=status_val,
                claim_id=claim_id,
                observation_id=data.get("observation_id"),
                result_hash=data.get("result_hash"),
                error=data.get("error"),
                caller_context=caller_ctx,
            )
            if "error" in res:
                code = res.get("code")
                err_msg = str(res.get("error", "")).lower()
                if code == "forbidden" or "unauthorized" in err_msg or "not authorized" in err_msg:
                    status_code = HTTPStatus.FORBIDDEN
                elif code == "not_found" or "not found" in err_msg:
                    status_code = HTTPStatus.NOT_FOUND
                elif (
                    code == "conflict"
                    or "already recorded" in err_msg
                    or "already been consumed" in err_msg
                    or "replayed" in err_msg
                ):
                    status_code = HTTPStatus.CONFLICT
                else:
                    status_code = HTTPStatus.BAD_REQUEST
                self._send_json(status_code, res)
                return

            self._send_json(HTTPStatus.OK, res)
            return

        if path == "/v1/policy/canary":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            cand_yaml = str(data.get("candidate_yaml", ""))
            limit = int(data.get("limit", 100))
            try:
                canary_res = services.run_canary_on_candidate(cand_yaml, limit=limit)
                self._send_json(HTTPStatus.OK, canary_res)
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Canary execution failed: {exc}"},
                )
            return

        if path == "/v1/simulate":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            try:
                sim_res = services.simulate_dry_run(
                    tool=str(data.get("tool", "")),
                    verb=str(data.get("verb", "other")),
                    resource=str(data.get("resource", "")),
                    params=data.get("params"),
                    session_id=str(data.get("session_id", "default")),
                    provenance=data.get("provenance"),
                )
                self._send_json(HTTPStatus.OK, sim_res)
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Simulation failed: {exc}"})
            return

        if path == "/v1/observations/verify":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            resource = data.get("resource")
            claim = data.get("claim")
            if not resource or not claim:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Fields 'resource' and 'claim' are required"},
                )
                return

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            try:
                ttl_val = float(data.get("ttl_seconds", 60.0))
            except (TypeError, ValueError):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'ttl_seconds' must be a number", "code": "invalid_ttl"},
                )
                return

            res = services.verify_state(
                resource=str(resource),
                claim=str(claim),
                crossing_id=data.get("crossing_id"),
                claim_id=data.get("claim_id"),
                expected_digest=data.get("expected_digest"),
                ttl_seconds=ttl_val,
                caller_context=caller_ctx,
            )
            if "error" in res and res.get("status") == "error" and "code" in res:
                code = res.get("code")
                if code == "forbidden":
                    status_code = HTTPStatus.FORBIDDEN
                elif code in ("not_found", "claim_not_found"):
                    status_code = HTTPStatus.NOT_FOUND
                elif code == "conflict":
                    status_code = HTTPStatus.CONFLICT
                else:
                    status_code = HTTPStatus.BAD_REQUEST
                self._send_json(status_code, res)
                return
            self._send_json(HTTPStatus.OK, res)
            return

        if path == "/v1/trace/links":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            req_fields = ("source_id", "source_type", "relation", "target_id", "target_type")
            missing = [f for f in req_fields if not data.get(f)]
            if missing:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Missing required fields: {', '.join(missing)}"},
                )
                return

            try:
                link = services.record_causal_link(
                    source_id=str(data["source_id"]),
                    source_type=data["source_type"],
                    relation=data["relation"],
                    target_id=str(data["target_id"]),
                    target_type=data["target_type"],
                    metadata=data.get("metadata"),
                )
                self._send_json(HTTPStatus.CREATED, link)
            except CycleDetectedError as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": str(exc), "code": "cycle_detected"},
                )
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Failed to record link: {exc}"})
            return

        if path == "/v1/handoffs":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            handoff_req_fields = (
                "task_id",
                "initiator_agent_id",
                "assigned_agent_id",
                "verifier_agent_id",
            )
            missing = [f for f in handoff_req_fields if not data.get(f)]
            if missing:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Missing required fields: {', '.join(missing)}"},
                )
                return

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            initiator = str(data["initiator_agent_id"])
            if caller_ctx.authenticated and not caller_ctx.is_agent_allowed(initiator):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": (
                            f"Principal '{caller_ctx.principal_id}' cannot initiate "
                            f"handoff as '{initiator}'"
                        ),
                        "code": "unauthorized_principal",
                    },
                )
                return

            try:
                hnd = services.create_task_handoff(
                    task_id=str(data["task_id"]),
                    initiator_agent_id=initiator,
                    assigned_agent_id=str(data["assigned_agent_id"]),
                    verifier_agent_id=str(data["verifier_agent_id"]),
                    allowed_verbs=data.get("allowed_verbs", ()),
                    allowed_resources=data.get("allowed_resources", ()),
                    prior_crossings=data.get("prior_crossings", ()),
                    prior_observations=data.get("prior_observations", ()),
                    assertions=data.get("assertions"),
                    ttl_seconds=float(data.get("ttl_seconds", 3600.0)),
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.CREATED, hnd)
            except UnauthorizedAgentHandoffError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_agent"},
                )
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": f"Failed to create handoff: {exc}"}
                )
            return

        if path.startswith("/v1/handoffs/") and path.endswith("/advance"):
            hnd_id = path[len("/v1/handoffs/") : -len("/advance")]
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            caller_id = data.get("caller_agent_id")
            next_id = data.get("next_agent_id")
            if not caller_id or not next_id:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Fields 'caller_agent_id' and 'next_agent_id' are required"},
                )
                return

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            if caller_ctx.authenticated and not caller_ctx.is_agent_allowed(str(caller_id)):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": (
                            f"Principal '{caller_ctx.principal_id}' cannot advance "
                            f"handoff as '{caller_id}'"
                        ),
                        "code": "unauthorized_principal",
                    },
                )
                return

            try:
                advanced = services.advance_task_handoff(
                    hnd_id,
                    caller_agent_id=str(caller_id),
                    next_agent_id=str(next_id),
                    crossing_id=data.get("crossing_id"),
                    observation_id=data.get("observation_id"),
                    new_assertions=data.get("new_assertions"),
                    allowed_verbs=data.get("allowed_verbs"),
                    allowed_resources=data.get("allowed_resources"),
                    ttl_seconds=float(data.get("ttl_seconds", 3600.0)),
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.OK, advanced)
            except UnauthorizedAgentHandoffError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_agent"},
                )
            except ExpiredHandoffError as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": str(exc), "code": "expired_handoff"},
                )
            except HandoffError as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": str(exc), "code": "handoff_error"},
                )
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": f"Failed to advance handoff: {exc}"}
                )
            return

        if path.startswith("/v1/handoffs/") and path.endswith("/verify"):
            hnd_id = path[len("/v1/handoffs/") : -len("/verify")]
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            verifier_id = data.get("verifier_agent_id")
            if not verifier_id:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'verifier_agent_id' is required"},
                )
                return

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            if caller_ctx.authenticated and not caller_ctx.is_agent_allowed(str(verifier_id)):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": (
                            f"Principal '{caller_ctx.principal_id}' cannot verify "
                            f"handoff as '{verifier_id}'"
                        ),
                        "code": "unauthorized_principal",
                    },
                )
                return

            try:
                result = services.verify_task_handoff(
                    hnd_id,
                    verifier_agent_id=str(verifier_id),
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.OK, result)
            except UnauthorizedAgentHandoffError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_agent"},
                )
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": f"Failed to verify handoff: {exc}"}
                )
            return

        if path == "/v1/leases":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            resource = data.get("resource")
            agent_id = data.get("owner_agent_id") or data.get("agent_id")
            session_id = data.get("session_id") or "default"
            if not resource or not agent_id:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": (
                            "Fields 'resource' and 'owner_agent_id' (or 'agent_id') are required"
                        )
                    },
                )
                return

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            if caller_ctx.authenticated and not caller_ctx.is_agent_allowed(str(agent_id)):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": (
                            f"Principal '{caller_ctx.principal_id}' cannot acquire "
                            f"lease as '{agent_id}'"
                        ),
                        "code": "unauthorized_principal",
                    },
                )
                return

            res = services.acquire_resource_lease(
                resource=str(resource),
                owner_agent_id=str(agent_id),
                session_id=str(session_id),
                mode=data.get("mode", "exclusive"),
                ttl_seconds=float(data.get("ttl_seconds", 60.0)),
                metadata=data.get("metadata"),
                caller_context=caller_ctx,
            )
            if res.get("status") == "conflict":
                self._send_json(HTTPStatus.CONFLICT, res)
            elif res.get("status") == "error":
                status = (
                    HTTPStatus.FORBIDDEN
                    if "not authorized" in str(res.get("error", "")).lower()
                    else HTTPStatus.BAD_REQUEST
                )
                self._send_json(status, res)
            else:
                self._send_json(HTTPStatus.CREATED, res)
            return

        if path.startswith("/v1/leases/") and path.endswith("/release"):
            lid = path[len("/v1/leases/") : -len("/release")]
            try:
                data = self._read_json_body()
            except Exception:
                data = {}
            owner = data.get("owner_agent_id") or data.get("agent_id")
            if not owner or not str(owner).strip():
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": (
                            "Field 'owner_agent_id' (or 'agent_id') is required to release lease"
                        )
                    },
                )
                return

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            if caller_ctx.authenticated and not caller_ctx.is_agent_allowed(str(owner)):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": (
                            f"Principal '{caller_ctx.principal_id}' cannot release lease "
                            f"owned by '{owner}'"
                        ),
                        "code": "unauthorized_principal",
                    },
                )
                return

            res = services.release_resource_lease(
                lid, owner_agent_id=str(owner), caller_context=caller_ctx
            )
            if not res.get("released"):
                err_msg = str(res.get("error", "")).lower()
                status = (
                    HTTPStatus.FORBIDDEN if "not authorized" in err_msg else HTTPStatus.NOT_FOUND
                )
                fallback_msg = f"Lease '{lid}' not found, already released, or unauthorized"
                self._send_json(
                    status,
                    {"error": res.get("error", fallback_msg)},
                )
            else:
                self._send_json(HTTPStatus.OK, res)
            return

        if path == "/v1/freeze":
            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            if caller_ctx.authenticated and not caller_ctx.is_trusted_operator:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Only trusted operators may freeze the system",
                        "code": "forbidden",
                    },
                )
                return

            self.server.boundary.freeze()
            self._send_json(
                HTTPStatus.OK,
                {"frozen": True, "message": "Kill switch activated: system frozen"},
            )
            return

        if path == "/v1/unfreeze":
            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            if caller_ctx.authenticated and not caller_ctx.is_trusted_operator:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Only trusted operators may unfreeze the system",
                        "code": "forbidden",
                    },
                )
                return

            self.server.boundary.unfreeze()
            self._send_json(HTTPStatus.OK, {"frozen": False, "message": "System unfrozen"})
            return

        if path == "/v1/delegations":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            delegation_req_fields = ("delegator_id", "delegatee_id", "allowed_agents", "scopes")
            missing = [f for f in delegation_req_fields if f not in data]
            if missing:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Missing required fields: {', '.join(missing)}"},
                )
                return

            try:
                caller_ctx = self._get_caller_context()
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
                return

            try:
                grant = services.register_delegation(
                    delegator_id=str(data["delegator_id"]),
                    delegatee_id=str(data["delegatee_id"]),
                    allowed_agents=data["allowed_agents"],
                    scopes=data["scopes"],
                    grant_id=data.get("grant_id"),
                    ttl_seconds=float(data["ttl_seconds"]) if "ttl_seconds" in data else None,
                    audience=str(data["audience"]).strip()
                    if "audience" in data and data["audience"]
                    else None,
                    max_depth=int(data["max_depth"]) if "max_depth" in data else 1,
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.CREATED, grant)
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Failed to register delegation: {exc}"},
                )
            return

        if path == "/v1/sessions":
            try:
                data = self._read_json_body()
            except Exception:
                data = {}

            try:
                sess = services.create_session(
                    principal_id=data.get("principal_id"),
                    trust_domain=str(data.get("trust_domain", "default")),
                    session_id=data.get("session_id"),
                    metadata=data.get("metadata"),
                    ttl_seconds=float(data.get("ttl_seconds", 3600.0)),
                    caller_context=caller_ctx,
                )
                self._send_json(HTTPStatus.CREATED, sess)
            except IdentitySecurityError as exc:
                self._send_forbidden(str(exc))
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": f"Failed to create session: {exc}"}
                )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route '{path}' not found"})

    def do_DELETE(self) -> None:
        if not self._validate_request():
            return
        if not self._validate_nonce_and_timestamp():
            return
        if not self._check_auth():
            return

        parts = urlsplit(self.path)
        path = parts.path.rstrip("/")
        services = self.server.services

        origin = self.headers.get("Origin")
        if origin and not self._allowed_origin():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Forbidden: cross-origin browser request rejected"},
            )
            return

        allowed, caller_ctx = self._authorize_route("DELETE", path)
        if not allowed or caller_ctx is None:
            return

        if path.startswith("/v1/trace/links/"):
            link_id = path[len("/v1/trace/links/") :]
            deleted = services.delete_causal_link(link_id)
            if deleted:
                self._send_json(HTTPStatus.OK, {"deleted": True, "link_id": link_id})
            else:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": f"Causal link '{link_id}' not found"},
                )
            return

        if path.startswith("/v1/delegations/"):
            grant_id = path[len("/v1/delegations/") :]
            try:
                success = services.revoke_delegation(grant_id, caller_context=caller_ctx)
                if success:
                    self._send_json(HTTPStatus.OK, {"revoked": True, "grant_id": grant_id})
                else:
                    self._send_json(
                        HTTPStatus.NOT_FOUND,
                        {"error": f"Delegation grant '{grant_id}' not found"},
                    )
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Failed to revoke delegation: {exc}"},
                )
            return

        if path.startswith("/v1/sessions/"):
            sid = path[len("/v1/sessions/") :]
            try:
                success = services.revoke_session(sid, caller_context=caller_ctx)
                if success:
                    self._send_json(HTTPStatus.OK, {"revoked": True, "session_id": sid})
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Session '{sid}' not found"})
            except IdentitySecurityError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_principal"},
                )
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Failed to revoke session: {exc}"},
                )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route '{path}' not found"})

    def _render_dashboard_html(self) -> str:
        """Render the complete, self-contained Actentra Operator Console."""
        console_path = Path(__file__).parent / "console.html"
        if console_path.exists():
            return console_path.read_text(encoding="utf-8")
        return "<html><body><h2>Actentra Console HTML template missing</h2></body></html>"


class ActentraHTTPServer(ThreadingHTTPServer):
    """Threading HTTPServer for Actentra gateway with persistence, TLS, and scoped executors."""

    def __init__(
        self,
        server_address: tuple[str, int],
        boundary: Boundary,
        *,
        executor_registry: ExecutorRegistry | None = None,
        approval_ttl_seconds: float = 300.0,
        auth_token: str | None = None,
        token_principals: dict[str, Any] | None = None,
        cert_principals: dict[str, Any] | MTLSPrincipalRegistry | None = None,
        unsafe_allow_remote: bool = False,
        deployment_mode: DeploymentMode | str = DeploymentMode.LOCAL,
        ssl_context: ssl.SSLContext | None = None,
        certfile: str | Path | None = None,
        keyfile: str | Path | None = None,
        key_password: str | None = None,
        ca_certs: str | Path | None = None,
        require_client_cert: bool = False,
        allowed_hosts: tuple[str, ...] | list[str] | None = None,
        trusted_proxies: tuple[str, ...] | list[str] | None = None,
        request_timeout: float = 30.0,
    ) -> None:
        host = server_address[0]
        mode = (
            DeploymentMode(deployment_mode) if isinstance(deployment_mode, str) else deployment_mode
        )
        effective_token = auth_token or os.environ.get("ACTENTRA_GATEWAY_TOKEN")
        is_remote_allowed = (
            unsafe_allow_remote
            or bool(os.environ.get("ACTENTRA_UNSAFE_ALLOW_REMOTE"))
            or mode != DeploymentMode.LOCAL
        )
        is_remote_mode = mode in (DeploymentMode.REMOTE, DeploymentMode.PRIVATE_NETWORK)

        if host not in _LOOPBACK_HOSTS or is_remote_mode:
            if not is_remote_allowed and not is_remote_mode:
                raise ValueError(
                    f"Refusing to bind Actentra Gateway to non-loopback address {host!r} "
                    "without explicit remote authorization (--unsafe-allow-remote)"
                )
            if (not effective_token or not effective_token.strip()) and not token_principals:
                raise ValueError(
                    f"Refusing to bind Actentra Gateway to non-loopback address {host!r} "
                    "without an authentication token. Remote interfaces require "
                    "token authentication."
                )

            # Enforce TLS on non-loopback or remote deployment modes (ACT-02)
            if ssl_context is None:
                if certfile and keyfile:
                    ssl_context = create_tls_context(
                        certfile=certfile,
                        keyfile=keyfile,
                        key_password=key_password,
                        ca_certs=ca_certs,
                        require_client_cert=require_client_cert,
                    )
                else:
                    addr_desc = (
                        f"non-loopback address {host!r}"
                        if host not in _LOOPBACK_HOSTS
                        else f"deployment mode '{mode}'"
                    )
                    raise ValueError(
                        f"Refusing to bind Actentra Gateway to {addr_desc} "
                        "without TLS. Remote communication must use authenticated TLS transport. "
                        "Plaintext remote HTTP is prohibited."
                    )
        elif ssl_context is None and certfile and keyfile:
            ssl_context = create_tls_context(
                certfile=certfile,
                keyfile=keyfile,
                key_password=key_password,
                ca_certs=ca_certs,
                require_client_cert=require_client_cert,
            )

        super().__init__(server_address, ActentraHTTPHandler)
        self.deployment_mode = mode
        self.boundary = boundary
        self.approval_ttl_seconds = approval_ttl_seconds
        self.auth_token = effective_token
        self.token_principals = token_principals
        if isinstance(cert_principals, MTLSPrincipalRegistry):
            self.cert_registry: MTLSPrincipalRegistry | None = cert_principals
        elif isinstance(cert_principals, dict):
            self.cert_registry = MTLSPrincipalRegistry.from_dict(cert_principals)
        else:
            self.cert_registry = None
        self.require_client_cert = require_client_cert
        self.allowed_hosts = tuple(allowed_hosts) if allowed_hosts else ()
        self.trusted_proxies = frozenset(trusted_proxies) if trusted_proxies else frozenset()
        self.request_timeout = request_timeout

        self._revoked_tokens: set[str] = set()
        self._token_lock = threading.Lock()
        self._seen_nonces: dict[str, float] = {}
        self._nonce_lock = threading.Lock()

        self.ssl_context: ssl.SSLContext | None = ssl_context
        self.is_tls: bool = ssl_context is not None
        if ssl_context is not None:
            self.socket = ssl_context.wrap_socket(self.socket, server_side=True)

        self.services = AppServices(
            boundary,
            executor_registry=executor_registry,
            approval_ttl_seconds=approval_ttl_seconds,
        )
        self.delegation_registry = self.services.delegation_registry

    def revoke_token(self, token: str) -> None:
        """Revoke a bearer token dynamically."""
        with self._token_lock:
            self._revoked_tokens.add(token)

    def rotate_token(self, old_token: str, new_token: str) -> None:
        """Rotate server authentication token, revoking the previous one."""
        with self._token_lock:
            self._revoked_tokens.add(old_token)
            self.auth_token = new_token

    def rotate_principal_token(self, old_token: str, new_token: str) -> None:
        """Rotate a principal-specific token in token_principals, revoking old_token."""
        with self._token_lock:
            self._revoked_tokens.add(old_token)
            if self.token_principals is not None and old_token in self.token_principals:
                entry = self.token_principals.pop(old_token)
                self.token_principals[new_token] = entry

    def revoke_certificate(self, fingerprint: str, *, reason: str = "manual_revocation") -> None:
        """Revoke an mTLS client certificate fingerprint immediately."""
        if self.cert_registry is not None:
            self.cert_registry.revoke_certificate(fingerprint, reason=reason)

    def rotate_certificate(
        self,
        principal_id: str,
        *,
        new_fingerprint: str | None = None,
        new_san_uri: str | None = None,
        old_fingerprint: str | None = None,
        revoke_old: bool = True,
    ) -> Any:
        """Rotate an mTLS client certificate for a registered principal."""
        if self.cert_registry is None:
            raise IdentitySecurityError("No cert_registry configured on server")
        return self.cert_registry.rotate_certificate(
            principal_id,
            new_fingerprint=new_fingerprint,
            new_san_uri=new_san_uri,
            old_fingerprint=old_fingerprint,
            revoke_old=revoke_old,
        )

    def is_token_revoked(self, token: str) -> bool:
        """Check whether a token has been revoked."""
        with self._token_lock:
            return token in self._revoked_tokens

    def check_and_record_nonce(self, nonce: str, max_age_seconds: float = 300.0) -> bool:
        """Check if nonce has been seen. If fresh, record and return True. If seen, return False."""
        now = time.time()
        with self._nonce_lock:
            cutoff = now - max_age_seconds
            expired = [n for n, ts in self._seen_nonces.items() if ts < cutoff]
            for n in expired:
                del self._seen_nonces[n]

            if nonce in self._seen_nonces:
                return False
            self._seen_nonces[nonce] = now
            return True

    def add_pending(self, envelope: Any, decision: Any) -> None:
        """Add pending approval to persistent SQLite store."""
        self.boundary.receipt_store.add_pending_approval(
            envelope=envelope,
            decision=decision,
            ttl_seconds=self.approval_ttl_seconds,
        )

    def clean_expired_pending(self) -> None:
        """Clean expired approvals in persistent SQLite store."""
        self.boundary.receipt_store.cleanup_expired_approvals()

    def resolve_pending(self, crossing_id: str, *, approved: bool) -> PendingCrossing | None:
        """Resolve pending approval in persistent store."""
        res = self.boundary.receipt_store.resolve_pending_approval(crossing_id, approved=approved)
        if res is None:
            return None
        if approved:
            self.boundary.grant_approval(
                canonical_hash=res.canonical_hash,
                session_id=res.session_id,
            )
        return PendingCrossing(
            crossing_id=res.crossing_id,
            session_id=res.session_id,
            canonical_hash=res.canonical_hash,
            tool=res.tool,
            verb=res.verb,
            resource=res.resource,
            risk_tags=res.risk_tags,
            reason=res.reason,
            ts=res.ts,
            expires_at=res.expires_at,
        )

    @property
    def pending_crossings(self) -> dict[str, PendingCrossing]:
        """In-memory dictionary compatibility view over persistent store."""
        records = self.boundary.receipt_store.list_pending_approvals(status="pending")
        return {
            r.crossing_id: PendingCrossing(
                crossing_id=r.crossing_id,
                session_id=r.session_id,
                canonical_hash=r.canonical_hash,
                tool=r.tool,
                verb=r.verb,
                resource=r.resource,
                risk_tags=r.risk_tags,
                reason=r.reason,
                ts=r.ts,
                expires_at=r.expires_at,
            )
            for r in records
        }


def create_gateway_server(
    boundary: Boundary,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    executor_registry: ExecutorRegistry | None = None,
    approval_ttl_seconds: float = 300.0,
    auth_token: str | None = None,
    token_principals: dict[str, Any] | None = None,
    cert_principals: dict[str, Any] | MTLSPrincipalRegistry | None = None,
    unsafe_allow_remote: bool = False,
    deployment_mode: DeploymentMode | str = DeploymentMode.LOCAL,
    ssl_context: ssl.SSLContext | None = None,
    certfile: str | Path | None = None,
    keyfile: str | Path | None = None,
    key_password: str | None = None,
    ca_certs: str | Path | None = None,
    require_client_cert: bool = False,
    allowed_hosts: tuple[str, ...] | list[str] | None = None,
    trusted_proxies: tuple[str, ...] | list[str] | None = None,
    request_timeout: float = 30.0,
) -> ActentraHTTPServer:
    """Create a configured ActentraHTTPServer ready to serve."""
    return ActentraHTTPServer(
        (host, port),
        boundary,
        executor_registry=executor_registry,
        approval_ttl_seconds=approval_ttl_seconds,
        auth_token=auth_token,
        token_principals=token_principals,
        cert_principals=cert_principals,
        unsafe_allow_remote=unsafe_allow_remote,
        deployment_mode=deployment_mode,
        ssl_context=ssl_context,
        certfile=certfile,
        keyfile=keyfile,
        key_password=key_password,
        ca_certs=ca_certs,
        require_client_cert=require_client_cert,
        allowed_hosts=allowed_hosts,
        trusted_proxies=trusted_proxies,
        request_timeout=request_timeout,
    )


def serve_http(
    boundary: Boundary,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    executor_registry: ExecutorRegistry | None = None,
    approval_ttl_seconds: float = 300.0,
    auth_token: str | None = None,
    token_principals: dict[str, Any] | None = None,
    cert_principals: dict[str, Any] | MTLSPrincipalRegistry | None = None,
    unsafe_allow_remote: bool = False,
    deployment_mode: DeploymentMode | str = DeploymentMode.LOCAL,
    ssl_context: ssl.SSLContext | None = None,
    certfile: str | Path | None = None,
    keyfile: str | Path | None = None,
    key_password: str | None = None,
    ca_certs: str | Path | None = None,
    require_client_cert: bool = False,
    allowed_hosts: tuple[str, ...] | list[str] | None = None,
    trusted_proxies: tuple[str, ...] | list[str] | None = None,
    request_timeout: float = 30.0,
) -> None:
    """Run the Actentra HTTP Gateway service synchronously."""
    server = create_gateway_server(
        boundary,
        host=host,
        port=port,
        executor_registry=executor_registry,
        approval_ttl_seconds=approval_ttl_seconds,
        auth_token=auth_token,
        token_principals=token_principals,
        cert_principals=cert_principals,
        unsafe_allow_remote=unsafe_allow_remote,
        deployment_mode=deployment_mode,
        ssl_context=ssl_context,
        certfile=certfile,
        keyfile=keyfile,
        key_password=key_password,
        ca_certs=ca_certs,
        require_client_cert=require_client_cert,
        allowed_hosts=allowed_hosts,
        trusted_proxies=trusted_proxies,
        request_timeout=request_timeout,
    )
    scheme = "https" if server.is_tls else "http"
    print(
        f"Actentra Gateway serving on {scheme}://{host}:{port} (Console: {scheme}://{host}:{port}/ui)"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
