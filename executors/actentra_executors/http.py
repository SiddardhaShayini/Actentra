"""Narrowly scoped, SSRF-defended HTTP connector for Actentra."""

from __future__ import annotations

import errno
import functools
import http.client
import ipaddress
import re
import socket
import ssl
import sys
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
        if (
            isinstance(ip, ipaddress.IPv6Address)
            and ip.ipv4_mapped is not None
            and _is_private_ip(str(ip.ipv4_mapped))
        ):
            return True
        return (
            not ip.is_global
            or ip.is_private
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
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{host_part}{port_part}{clean_path}{query_part}"


class PinningDNSResolver:
    """SSRF-safe DNS resolver that resolves once, validates all IPs, and pins connections."""

    def __init__(self, *, allow_private_ips: bool = False) -> None:
        self.allow_private_ips = allow_private_ips
        self._pinned: dict[str, str] = {}

    def get_pinned_ip(self, hostname: str) -> str | None:
        """Return previously pinned IP for hostname if resolved."""
        return self._pinned.get(hostname.lower().strip())

    def resolve_and_pin(self, host_or_url: str) -> str:
        """Resolve destination, validate against SSRF private/metadata rules, and pin IP."""
        candidate = host_or_url.strip()
        try:
            ip = ipaddress.ip_address(candidate)
            hostname = str(ip).lower()
        except ValueError:
            if "://" in candidate:
                parsed = urllib.parse.urlsplit(candidate)
                hostname = (parsed.hostname or "").lower().strip()
            elif ":" in candidate and not candidate.startswith("[") and candidate.count(":") > 1:
                # IPv6 literal without brackets
                parsed = urllib.parse.urlsplit(f"//[{candidate}]")
                hostname = (parsed.hostname or "").lower().strip()
            else:
                parsed = urllib.parse.urlsplit(f"//{candidate}")
                hostname = (parsed.hostname or "").lower().strip()

        if not hostname:
            raise ExecutorError(f"URL missing valid hostname: {host_or_url!r}")

        if hostname in self._pinned:
            return self._pinned[hostname]

        if _is_private_ip(hostname):
            if not self.allow_private_ips:
                raise ExecutorError(
                    f"Direct connection to private/metadata IP {hostname!r} is blocked (SSRF guard)"
                )
            self._pinned[hostname] = hostname
            return hostname

        try:
            ipaddress.ip_address(hostname)
            # Public IP literal
            self._pinned[hostname] = hostname
            return hostname
        except ValueError:
            pass

        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ExecutorError(f"DNS resolution failed for host {hostname!r}: {exc}") from exc

        if not addr_info:
            raise ExecutorError(f"DNS resolution returned no addresses for host {hostname!r}")

        resolved_ips: list[str] = []
        for _, _, _, _, sockaddr in addr_info:
            ip_str = str(sockaddr[0])
            if not self.allow_private_ips and _is_private_ip(ip_str):
                raise ExecutorError(
                    f"Host {hostname!r} resolves to private IP {ip_str!r}; blocked by SSRF defense"
                )
            resolved_ips.append(ip_str)

        pinned = resolved_ips[0]
        self._pinned[hostname] = pinned
        return pinned

    def get_pinned(self, hostname: str) -> str | None:
        """Return pinned IP for hostname if resolved during request lifecycle."""
        return self._pinned.get(hostname.lower())


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection connecting directly to a pre-validated, pinned destination IP."""

    def __init__(
        self,
        host: str,
        *args: Any,
        pinned_ip: str | None = None,
        allow_private_ips: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(host, *args, **kwargs)
        self.pinned_ip = pinned_ip
        self.allow_private_ips = allow_private_ips

    def connect(self) -> None:
        target_ip = self.pinned_ip or self.host
        if not self.allow_private_ips and _is_private_ip(target_ip):
            raise ExecutorError(
                f"Connection to private/metadata IP {target_ip!r} is blocked by SSRF defense"
            )
        sys.audit("http.client.connect", self, self.host, self.port)
        source_addr = getattr(self, "source_address", None)
        self.sock = socket.create_connection(
            (target_ip, self.port),
            self.timeout,
            source_addr,
        )
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            if e.errno != errno.ENOPROTOOPT:
                raise
        peer = self.sock.getpeername()
        peer_ip = str(peer[0])
        if not self.allow_private_ips and _is_private_ip(peer_ip):
            self.sock.close()
            raise ExecutorError(
                f"Connected peer IP {peer_ip!r} is private/metadata; blocked by SSRF defense"
            )
        if self.pinned_ip and peer_ip != self.pinned_ip:
            self.sock.close()
            raise ExecutorError(
                f"Connected peer IP {peer_ip!r} does not match pinned IP {self.pinned_ip!r}"
            )
        tunnel_host = getattr(self, "_tunnel_host", None)
        if tunnel_host:
            tunnel_fn = getattr(self, "_tunnel", None)
            if callable(tunnel_fn):
                tunnel_fn()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects to pinned IP and validates TLS certs against hostname."""

    def __init__(
        self,
        host: str,
        *args: Any,
        context: ssl.SSLContext | None = None,
        check_hostname: bool | None = None,
        pinned_ip: str | None = None,
        allow_private_ips: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(host, *args, context=context, **kwargs)
        if check_hostname is not None and context is not None:
            context.check_hostname = check_hostname
        self.pinned_ip = pinned_ip
        self.allow_private_ips = allow_private_ips
        self._ssl_ctx = context

    def connect(self) -> None:
        target_ip = self.pinned_ip or self.host
        if not self.allow_private_ips and _is_private_ip(target_ip):
            raise ExecutorError(
                f"Connection to private/metadata IP {target_ip!r} is blocked by SSRF defense"
            )
        sys.audit("http.client.connect", self, self.host, self.port)
        source_addr = getattr(self, "source_address", None)
        self.sock = socket.create_connection(
            (target_ip, self.port),
            self.timeout,
            source_addr,
        )
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            if e.errno != errno.ENOPROTOOPT:
                raise
        peer = self.sock.getpeername()
        peer_ip = str(peer[0])
        if not self.allow_private_ips and _is_private_ip(peer_ip):
            self.sock.close()
            raise ExecutorError(
                f"Connected peer IP {peer_ip!r} is private/metadata; blocked by SSRF defense"
            )
        if self.pinned_ip and peer_ip != self.pinned_ip:
            self.sock.close()
            raise ExecutorError(
                f"Connected peer IP {peer_ip!r} does not match pinned IP {self.pinned_ip!r}"
            )
        tunnel_host = getattr(self, "_tunnel_host", None)
        if tunnel_host:
            tunnel_fn = getattr(self, "_tunnel", None)
            if callable(tunnel_fn):
                tunnel_fn()
        server_hostname = str(tunnel_host or self.host)
        ctx = self._ssl_ctx or ssl.create_default_context()
        self.sock = ctx.wrap_socket(self.sock, server_hostname=server_hostname)


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    """urllib HTTPHandler using PinnedHTTPConnection to eliminate DNS rebinding."""

    def __init__(self, resolver: PinningDNSResolver) -> None:
        super().__init__()
        self._resolver = resolver

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        parsed = urllib.parse.urlsplit(f"//{req.host}")
        hostname = (parsed.hostname or "").lower()
        pinned_ip = self._resolver.resolve_and_pin(hostname)
        conn_factory = functools.partial(
            PinnedHTTPConnection,
            pinned_ip=pinned_ip,
            allow_private_ips=self._resolver.allow_private_ips,
        )
        return self.do_open(conn_factory, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """urllib HTTPSHandler using PinnedHTTPSConnection with SNI and cert hostname validation."""

    def __init__(
        self,
        resolver: PinningDNSResolver,
        context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(context=context)
        self._resolver = resolver
        self._ssl_context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        parsed = urllib.parse.urlsplit(f"//{req.host}")
        hostname = (parsed.hostname or "").lower()
        pinned_ip = self._resolver.resolve_and_pin(hostname)
        conn_factory = functools.partial(
            PinnedHTTPSConnection,
            pinned_ip=pinned_ip,
            allow_private_ips=self._resolver.allow_private_ips,
        )
        return self.do_open(conn_factory, req, context=self._ssl_context)


class SSRFSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Intercept and validate all HTTP redirects against SSRF and host policy (Finding 2)."""

    def __init__(
        self,
        validator: Callable[[str], Any],
        max_redirects: int = 5,
        resolver: PinningDNSResolver | None = None,
    ) -> None:
        super().__init__()
        self._validator = validator
        self._max_redirects = max_redirects
        self._resolver = resolver
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
        base_url = req.full_url if isinstance(getattr(req, "full_url", None), str) else ""
        full_newurl = urllib.parse.urljoin(base_url, newurl) if base_url else newurl
        # Validate redirected destination before following
        self._validator(full_newurl)
        if self._resolver is not None:
            new_parsed = urllib.parse.urlsplit(full_newurl)
            new_hostname = (new_parsed.hostname or "").lower()
            if new_hostname:
                self._resolver.resolve_and_pin(new_hostname)
        return super().redirect_request(req, fp, code, msg, headers, full_newurl)


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

    def _verify_destination_ip(
        self,
        hostname: str,
        allow_private: bool,
        resolver: PinningDNSResolver | None = None,
    ) -> str:
        """Resolve hostname and reject private / metadata IP ranges unless allowed."""
        res = (
            resolver
            if resolver is not None
            else PinningDNSResolver(allow_private_ips=allow_private)
        )
        return res.resolve_and_pin(hostname)

    def _validate_url_target(
        self,
        target_url: str,
        constraints: dict[str, Any],
        allow_private: bool,
        resolver: PinningDNSResolver | None = None,
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
        self._verify_destination_ip(hostname, allow_private, resolver=resolver)
        return canon

    def execute(self, envelope: ActionEnvelope, decision: Decision) -> dict[str, Any]:
        """Execute an authorized HTTP action according to constraints."""
        tool = envelope.action.tool
        if not tool.startswith(("http.", "net.http", "webhook.")):
            raise ExecutorError(f"Unsupported tool for ScopedHTTPExecutor: {tool!r}")

        constraints = dict(decision.constraints)
        allow_private = bool(constraints.get("allow_private_ips", self._allow_private_ips))
        resolver = PinningDNSResolver(allow_private_ips=allow_private)
        canon_url = self._validate_url_target(
            envelope.action.resource, constraints, allow_private, resolver=resolver
        )

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
            self._validate_url_target(new_url, constraints, allow_private, resolver=resolver)

        redirect_handler = SSRFSafeRedirectHandler(
            validator=redirect_validator,
            max_redirects=max_redirects,
            resolver=resolver,
        )
        pinned_http_handler = PinnedHTTPHandler(resolver)
        pinned_https_handler = PinnedHTTPSHandler(resolver)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            redirect_handler,
            pinned_http_handler,
            pinned_https_handler,
        )

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
