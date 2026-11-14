"""Narrowly scoped, SSRF-defended HTTP connector for Actentra."""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError

from actentra.boundary import Boundary
from actentra.secrets import SecretsBroker, SecretsError
from actentra_core.canonicalize import CanonicalizationError, canonicalize_unicode
from actentra_core.envelope import ActionEnvelope, ProvenanceItem
from actentra_core.verdict import Decision
from actentra_executors.fs import ExecutorError

_DEFAULT_MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB
_DEFAULT_TIMEOUT_SECONDS = 15.0
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ALL_METHODS = _SAFE_METHODS | _MUTATING_METHODS
_SECRET_REF_PATTERN = re.compile(r"secret:([a-zA-Z0-9_\-]+)")


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to private, loopback, link-local, or cloud metadata ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def canonicalize_url(raw_url: str) -> str:
    """Normalize and validate an HTTP(S) URL.

    Rejects non-HTTP schemes, userinfo/credentials in URLs, NUL bytes,
    and unparseable hostnames.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise CanonicalizationError("URL must be a non-empty string")

    clean = canonicalize_unicode(raw_url).strip()
    try:
        parsed = urllib.parse.urlsplit(clean)
    except Exception as exc:
        raise CanonicalizationError(f"Malformed URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise CanonicalizationError(
            f"Unsupported URL scheme {scheme!r}; only 'http' and 'https' are permitted"
        )

    if parsed.username or parsed.password:
        raise CanonicalizationError("Embedded credentials (userinfo) in URLs are forbidden")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise CanonicalizationError("URL must have a valid hostname")

    port_part = ""
    if parsed.port is not None and (
        (scheme == "http" and parsed.port != 80) or (scheme == "https" and parsed.port != 443)
    ):
        port_part = f":{parsed.port}"

    path = parsed.path or "/"
    # Clean redundant slashes in path
    clean_path = re.sub(r"/{2,}", "/", path)

    query_part = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{hostname}{port_part}{clean_path}{query_part}"


class SSRFSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Intercept and validate all HTTP redirects against SSRF and host policy (Finding 2)."""

    def __init__(
        self,
        validator: Callable[[str], Any],
        max_redirects: int = 5,
    ) -> None:
        super().__init__()
        self._validator = validator
        self._max_redirects = max_redirects
        self._count = 0

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        self._count += 1
        if self._count > self._max_redirects:
            raise ExecutorError(f"HTTP redirect limit exceeded ({self._max_redirects})")
        # Validate redirected destination before following
        self._validator(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ScopedHTTPExecutor:
    """SSRF-defended HTTP client executor bound by policy constraints."""

    def __init__(
        self,
        *,
        allowed_hosts: list[str] | tuple[str, ...] | None = None,
        allow_private_ips: bool = False,
        default_timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        default_max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        secrets_broker: SecretsBroker | None = None,
    ) -> None:
        self._allowed_hosts = (
            tuple(h.lower().strip() for h in allowed_hosts) if allowed_hosts else None
        )
        self._allow_private_ips = allow_private_ips
        self._default_timeout = default_timeout_seconds
        self._default_max_bytes = default_max_response_bytes
        self._secrets_broker = secrets_broker

    def _check_host_allowed(self, hostname: str, constraints: dict[str, Any]) -> None:
        host_rules = constraints.get("allowed_hosts") or self._allowed_hosts
        if host_rules is None:
            return

        normalized_host = hostname.lower()
        for rule in host_rules:
            r = str(rule).lower().strip()
            if r.startswith("*."):
                suffix = r[1:]  # e.g. .example.com
                if normalized_host.endswith(suffix) and normalized_host != suffix[1:]:
                    return
            elif normalized_host == r:
                return

        raise ExecutorError(
            f"Host {hostname!r} is not in the allowed hosts list: {list(host_rules)}"
        )

    def _verify_destination_ip(self, hostname: str, allow_private: bool) -> None:
        """Resolve hostname and reject private / metadata IP ranges unless allowed."""
        if allow_private:
            return

        if _is_private_ip(hostname):
            raise ExecutorError(
                f"Direct connection to private/metadata IP {hostname!r} is blocked (SSRF guard)"
            )

        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ExecutorError(f"DNS resolution failed for host {hostname!r}: {exc}") from exc

        for _, _, _, _, sockaddr in addr_info:
            ip_str = str(sockaddr[0])
            if _is_private_ip(ip_str):
                raise ExecutorError(
                    f"Host {hostname!r} resolves to private IP {ip_str!r}; blocked by SSRF defense"
                )

    def _validate_url_target(
        self, target_url: str, constraints: dict[str, Any], allow_private: bool
    ) -> str:
        """Validate destination URL against allowed schemes, host list, and private IP ranges."""
        try:
            canon = canonicalize_url(target_url)
        except CanonicalizationError as exc:
            raise ExecutorError(f"Invalid URL {target_url!r}: {exc}") from exc

        parsed = urllib.parse.urlsplit(canon)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise ExecutorError(f"Disallowed URL scheme {parsed.scheme!r}; only HTTP(S) permitted")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ExecutorError(f"URL missing valid hostname: {target_url!r}")

        self._check_host_allowed(hostname, constraints)
        self._verify_destination_ip(hostname, allow_private)
        return canon

    def execute(self, envelope: ActionEnvelope, decision: Decision) -> dict[str, Any]:
        """Execute an authorized HTTP action according to constraints."""
        tool = envelope.action.tool
        if not tool.startswith(("http.", "net.http", "webhook.")):
            raise ExecutorError(f"Unsupported tool for ScopedHTTPExecutor: {tool!r}")

        constraints = dict(decision.constraints)
        allow_private = bool(constraints.get("allow_private_ips", self._allow_private_ips))
        canon_url = self._validate_url_target(envelope.action.resource, constraints, allow_private)

        params = envelope.action.params
        method = str(params.get("method", "GET")).upper().strip()
        if method not in _ALL_METHODS:
            raise ExecutorError(f"Unsupported HTTP method: {method!r}")

        allowed_methods = constraints.get("allowed_methods")
        if isinstance(allowed_methods, list) and allowed_methods:
            norm_allowed = {str(m).upper().strip() for m in allowed_methods}
            if method not in norm_allowed:
                msg = (
                    f"Method {method!r} not permitted by constraint; allowed: "
                    f"{sorted(norm_allowed)}"
                )
                raise ExecutorError(msg)

        if constraints.get("read_only") and method not in _SAFE_METHODS:
            raise ExecutorError(f"read_only constraint prohibits mutating method {method!r}")

        timeout = float(constraints.get("timeout_seconds", self._default_timeout))
        max_bytes = int(constraints.get("max_response_bytes", self._default_max_bytes))

        # Configurable redirect policy with SSRF-safe validation (Finding 2)
        allow_redirects = bool(constraints.get("allow_redirects", True))
        max_redirects = int(constraints.get("max_redirects", 5)) if allow_redirects else 0

        # Prepare request headers
        raw_headers = params.get("headers") or {}
        if not isinstance(raw_headers, dict):
            raise ExecutorError("headers must be a dictionary")
        headers: dict[str, str] = {str(k): str(v) for k, v in raw_headers.items()}

        # Secrets injection via broker if configured
        secret_headers = constraints.get("secret_headers")
        if isinstance(secret_headers, dict):
            # secret_headers maps header_name to secret_value or secret:NAME reference
            for h_name, h_val in secret_headers.items():
                headers[str(h_name)] = str(h_val)

        # Resolve secret references in any header: "secret:NAME" or "Bearer secret:NAME"
        for h_name, h_val in list(headers.items()):
            if "secret:" in h_val:

                def _replace_secret(match: re.Match[str], header_key: str = h_name) -> str:
                    sec_name = match.group(1)
                    if self._secrets_broker is None:
                        raise ExecutorError(
                            "SecretsBroker is required to resolve secret reference "
                            f"'secret:{sec_name}' in header {header_key!r}"
                        )
                    try:
                        return self._secrets_broker.get_secret(sec_name)
                    except SecretsError as exc:
                        raise ExecutorError(
                            f"Failed to resolve secret reference 'secret:{sec_name}' "
                            f"in header {header_key!r}: {exc}"
                        ) from exc

                headers[h_name] = _SECRET_REF_PATTERN.sub(_replace_secret, h_val)

        # Prepare payload
        body_data: bytes | None = None
        raw_body = params.get("body")
        if raw_body is not None:
            if isinstance(raw_body, str):
                body_data = raw_body.encode("utf-8")
            elif isinstance(raw_body, (bytes, bytearray)):
                body_data = bytes(raw_body)
            else:
                raise ExecutorError("body must be a string or bytes")

        req = urllib.request.Request(  # noqa: S310
            url=canon_url,
            data=body_data,
            headers=headers,
            method=method,
        )

        def redirect_validator(new_url: str) -> None:
            self._validate_url_target(new_url, constraints, allow_private)

        redirect_handler = SSRFSafeRedirectHandler(
            validator=redirect_validator,
            max_redirects=max_redirects,
        )
        opener = urllib.request.build_opener(redirect_handler)

        try:
            with opener.open(req, timeout=timeout) as resp:  # noqa: S310
                status_code = int(resp.status)
                resp_headers = dict(resp.headers)
                # Bounded read to prevent memory bombs
                content_bytes = resp.read(max_bytes + 1)
                truncated = len(content_bytes) > max_bytes
                if truncated:
                    content_bytes = content_bytes[:max_bytes]

                try:
                    text_content = content_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    text_content = f"<binary data: {len(content_bytes)} bytes>"

                if self._secrets_broker is not None:
                    text_content = self._secrets_broker.redact(text_content)
                    resp_headers = {
                        k: self._secrets_broker.redact(str(v)) for k, v in resp_headers.items()
                    }

                return {
                    "status_code": status_code,
                    "url": canon_url,
                    "headers": resp_headers,
                    "body": text_content,
                    "byte_count": len(content_bytes),
                    "truncated": truncated,
                }
        except HTTPError as exc:
            err_body = exc.read(4096).decode("utf-8", errors="replace")
            err_reason = str(exc.reason)
            resp_headers_dict = dict(exc.headers)
            if self._secrets_broker is not None:
                err_body = self._secrets_broker.redact(err_body)
                err_reason = self._secrets_broker.redact(err_reason)
                resp_headers_dict = {
                    k: self._secrets_broker.redact(str(v)) for k, v in resp_headers_dict.items()
                }
            return {
                "status_code": exc.code,
                "url": canon_url,
                "headers": resp_headers_dict,
                "body": err_body,
                "byte_count": len(err_body.encode("utf-8")),
                "truncated": False,
                "error": err_reason,
            }
        except URLError as exc:
            err_msg = f"HTTP connection failed: {exc.reason}"
            if self._secrets_broker is not None:
                err_msg = self._secrets_broker.redact(err_msg)
            raise ExecutorError(err_msg) from exc
        except TimeoutError as exc:
            raise ExecutorError(f"HTTP request timed out after {timeout}s") from exc
        except ExecutorError as exc:
            if self._secrets_broker is not None:
                raise ExecutorError(self._secrets_broker.redact(str(exc))) from exc
            raise


class ScopedHTTPTools:
    """Agent-facing HTTP client mediated through an Actentra Boundary."""

    def __init__(self, boundary: Boundary, executor: ScopedHTTPExecutor) -> None:
        self._boundary = boundary
        self._executor = executor
        if self._executor._secrets_broker is None and boundary.secrets_broker is not None:
            self._executor._secrets_broker = boundary.secrets_broker

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> dict[str, Any]:
        """Perform an authorized HTTP GET request."""
        canon = canonicalize_url(url)
        result: dict[str, Any] = self._boundary.execute(
            tool="http.get",
            verb="network",
            resource=canon,
            params={"method": "GET", "headers": headers or {}},
            fn=self._executor.execute,
            provenance=provenance,
            user_goal=user_goal,
        )
        return result

    def post(
        self,
        url: str,
        body: str,
        *,
        headers: dict[str, str] | None = None,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> dict[str, Any]:
        """Perform an authorized HTTP POST request."""
        canon = canonicalize_url(url)
        result: dict[str, Any] = self._boundary.execute(
            tool="http.post",
            verb="network",
            resource=canon,
            params={"method": "POST", "body": body, "headers": headers or {}},
            fn=self._executor.execute,
            provenance=provenance,
            user_goal=user_goal,
        )
        return result
