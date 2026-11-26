# Actentra Security Remediation Report — Finding 02

**Target:** HTTP executor DNS rebinding and SSRF bypass  
**Affected Source:** `executors/actentra_executors/http.py:157-177,294-297`  
**Severity:** HIGH  
**Status:** **REMEDIATED**  
**Commit:** Separate dedicated remediation commit

---

## 1. Executive Summary

During the enterprise security audit of Actentra, Finding F-2 identified a critical Time-of-Check-Time-of-Use (TOCTOU) DNS rebinding vulnerability in `ScopedHTTPExecutor`. Although `_verify_destination_ip` inspected the destination hostname prior to making a request, the underlying standard library HTTP client (`urllib.request` / `http.client`) performed an independent, secondary DNS lookup during socket establishment. This allowed an attacker controlling a domain with short DNS TTL (e.g., 0-1s) to return a benign public IP during pre-validation and resolve to a loopback (`127.0.0.1`), private RFC 1918, or cloud metadata IP (`169.254.169.254`) on connect.

This vulnerability has been completely eliminated through a socket-level connection IP pinning architecture, post-connect peer IP verification, separate TLS SNI preservation, SSRF-safe redirect re-resolution and pinning, and environment proxy isolation.

---

## 2. Vulnerability Analysis

### Root Cause

1. **Dual DNS Resolution (TOCTOU):**
   `ScopedHTTPExecutor.execute()` called `_validate_url_target()` which invoked `socket.getaddrinfo()` to verify destination IP addresses. However, `urllib.request.build_opener().open()` was subsequently passed the hostname string. When `http.client.HTTPConnection.connect()` was called by urllib, `socket.create_connection((self.host, self.port))` performed a second, unconstrained DNS resolution.
2. **Missing Post-Connect Verification:**
   The connection establishment did not inspect the resulting socket's peer name (`sock.getpeername()`), allowing network routing anomalies or multi-homed resolution to connect to private subnets undetected.
3. **Multi-Record DNS Exploitation:**
   If a DNS response returned a mix of public and private IP addresses (e.g., round-robin or dual-stack IPv4/IPv6), the original check inspected only one address or could be bypassed depending on OS resolver order.
4. **Cloud Metadata & Non-Global Range Gaps:**
   Address validation checked `ip.is_private`, but omitted `not ip.is_global` (allowing Carrier-Grade NAT `100.64.0.0/10` and benchmark networks) and IPv4-mapped IPv6 representations (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`).
5. **Confused Deputy Proxies:**
   Ambient environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) could route requests through local or unauthenticated HTTP proxies, bypassing host and IP restrictions.

---

## 3. Remediation Architecture

The remediation introduces a defense-in-depth socket-level IP pinning design in `executors/actentra_executors/http.py`:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ScopedHTTPExecutor                              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      PinningDNSResolver                                │
│  - Resolves host once via socket.getaddrinfo                           │
│  - Verifies ALL returned IPs (rejects if ANY IP is non-global)         │
│  - Blocks loopback, private, link-local, CGNAT (100.64.0.0/10),        │
│    cloud metadata (169.254.169.254), and IPv4-mapped IPv6              │
│  - Caches pinned destination IP for request lifecycle                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
               ┌────────────────────┴────────────────────┐
               ▼                                         ▼
┌───────────────────────────────┐     ┌──────────────────────────────────┐
│     PinnedHTTPConnection      │     │      PinnedHTTPSConnection       │
│ - Connects to (pinned_ip,port)│     │ - Connects to (pinned_ip,port)   │
│ - Post-connect peer check:    │     │ - Post-connect peer check        │
│   sock.getpeername() == pinned│     │ - TLS wrap_socket preserves SNI: │
│ - Aborts before sending bytes │     │   server_hostname = self.host    │
└───────────────────────────────┘     └──────────────────────────────────┘
               ▲                                         ▲
               └────────────────────┬────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                    SSRFSafeRedirectHandler                             │
│  - Revalidates redirect URLs against policy and schemes (HTTP/S only)  │
│  - Re-resolves and pins destination IP for each redirect hop           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                  Proxy Isolation: ProxyHandler({})                     │
│  - Ignores ambient HTTP_PROXY/HTTPS_PROXY environment variables        │
└────────────────────────────────────────────────────────────────────────┘
```

### Key Technical Implementation Details

1. **`PinningDNSResolver`:**
   - Performs atomic single-resolution via `socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)`.
   - Iterates through all returned sockaddr tuples; if any resolved IP belongs to a private, loopback, link-local, CGNAT, benchmark, or cloud metadata range, resolution immediately fails with `ExecutorError`.
   - Pins the primary validated IP in an in-memory dictionary.
2. **`PinnedHTTPConnection` & `PinnedHTTPSConnection`:**
   - Overrides `connect()`: passes `(target_ip, self.port)` (where `target_ip = self.pinned_ip`) directly to `socket.create_connection`, entirely bypassing urllib/http.client hostname resolution.
   - Sets `TCP_NODELAY` and initiates audit events.
   - Enforces post-connect peer IP verification: inspects `peer_ip = str(self.sock.getpeername()[0])`. If `peer_ip` is private/non-global or does not match `self.pinned_ip`, `self.sock.close()` is called and `ExecutorError` is raised before transmitting any request bytes.
3. **Preserving TLS SNI and Certificate Validation:**
   - For HTTPS connections, `ctx.wrap_socket(self.sock, server_hostname=server_hostname)` passes the original hostname (`self.host`) as `server_hostname`, NOT the pinned IP.
   - This ensures TLS Server Name Indication (SNI) and Subject Alternative Name (SAN) certificate validation function strictly according to standard PKI semantics while the underlying TCP socket is pinned to the pre-validated IP.
4. **SSRF-Safe Redirects:**
   - `SSRFSafeRedirectHandler` validates every redirected URL with `urljoin`, validates scheme restrictions (blocking `file:`, `gopher:`, `ftp:`, etc.), enforces `allowed_hosts`, and resolves and pins the redirected host before following the hop.
5. **Proxy Isolation:**
   - Configures `urllib.request.ProxyHandler({})` explicitly in `build_opener()`, preventing ambient `HTTP_PROXY` / `HTTPS_PROXY` variables from acting as confused deputies.
6. **IPv6 URL Canonicalization:**
   - Corrected `canonicalize_url` to preserve RFC 3986 bracket notation (`f"[{hostname}]"`) for IPv6 address literals.

---

## 4. Verification and Proof of Remediation

### Adversarial Regression Suite (`tests/unit/test_security_finding_02_dns_rebinding.py`)

A comprehensive test suite implementing test target T-01 from `ADVERSARIAL_TEST_PLAN.md` was created:

| Test Case | Description | Result |
|---|---|---|
| `test_dns_rebinding_dual_resolution_attack_blocked_at_socket_connect` | Simulates DNS rebinding where validation returns public IP and connect lookup returns `127.0.0.1`. Asserts socket connects only to pinned public IP and never to loopback. | **PASS** |
| `test_dns_dual_resolution_multi_record_with_private_ip_immediately_blocked` | DNS returns mixed round-robin records `[93.184.216.34, 127.0.0.1]`. Asserts request is blocked before socket connection. | **PASS** |
| `test_post_connect_peer_ip_private_verification_aborts` | Socket peer name returns private IP. Asserts socket is immediately closed and `ExecutorError` raised. | **PASS** |
| `test_post_connect_peer_ip_mismatch_aborts` | Socket peer name returns mismatched IP (`93.184.216.99` vs `93.184.216.34`). Asserts connection aborted. | **PASS** |
| `test_redirect_dns_rebinding_to_metadata_service_blocked` | 302 redirect to domain attempting rebinding to AWS IMDS `169.254.169.254`. Asserts blocked before request. | **PASS** |
| `test_non_global_and_mapped_ip_ranges_blocked[15 IP variants]` | Parametrized test across loopback, RFC 1918, CGNAT `100.64.0.1`, benchmark `198.18.0.1`, IPv6 loopback `::1`, link-local `fe80::1`, and IPv4-mapped IPv6 `::ffff:169.254.169.254`. Asserts all rejected. | **PASS** |
| `test_https_sni_and_cert_validation_preserved_with_pinned_ip` | Verifies `wrap_socket` receives domain name for TLS SNI and SAN verification while socket connects to pinned IP. | **PASS** |
| `test_proxy_handler_overrides_environment_proxies` | Sets ambient `HTTP_PROXY` and verifies opener explicitly uses `ProxyHandler({})`. | **PASS** |
| `test_redirect_scheme_change_blocked` | Redirect to `file:///etc/passwd` rejected immediately before following. | **PASS** |
| `test_relative_redirect_resolution_and_pinning` | Relative path redirect correctly combined with base URL and pinned. | **PASS** |
| `test_allow_private_ips_override_permits_loopback_when_explicitly_configured` | Explicit `allow_private_ips=True` constraint allows internal services when opted in. | **PASS** |

### Suite Verification Results

- **Finding 02 Test Suite:** 25/25 passed in 0.69s.
- **Combined Security & HTTP Suite:** 56 passed, 2 skipped (Windows local socket permission) in 3.32s.
- **Full Fast Test Suite:** 204/204 passed in 40.5s.
- **Linting & Types:** `ruff check` (0 errors), `mypy` (37 source files clean).

---

## 5. Remaining Risks and Trust Model Limitations

1. **In-Process Python Boundary:**
   `ScopedHTTPExecutor` prevents SSRF and DNS rebinding for actions executed through the Actentra framework. However, an in-process agent with arbitrary Python execution permissions could import `socket` or third-party HTTP libraries directly. In enterprise environments, network-level egress filtering (e.g. Istio egress gateway, AWS security groups) must accompany SDK-level controls.
2. **DNS Over HTTPS / Upstream Resolver Trust:**
   `PinningDNSResolver` relies on the host OS `socket.getaddrinfo()`. If the upstream DNS resolver itself is compromised (cache poisoning at the recursive resolver level), pinning will bind to the poisoned IP. DNSSEC or authenticated recursive resolvers should be deployed at the OS/container level.
3. **Redirect Limits:**
   Redirect chains are strictly capped by `max_redirects` (default: 5) to prevent infinite redirect loops and resource exhaustion attacks.
