# Remediation Report: Finding 01 (Second-Pass) — Authentication Secret Bypass and Delegation Authority Forgery

**Audit Commit:** `02887cd`  
**First Remediation Commit:** `70b09e8`  
**Independent Validation Commit:** `35c9ed7`  
**Finding ID:** F-1 (Enterprise Security Audit)  
**Severity:** HIGH  
**Status:** VERIFIED REMEDIATED  
**Date:** 2026-11-20  

---

## 1. Executive Summary

During the initial remediation of Finding 01 (`70b09e8`), principal boundaries and scope checks were introduced. However, an independent security validation (`35c9ed7`) identified two critical security flaws that left F-1 un-remediated:

1. **Authentication Secret Bypass via Structured Bearer Tokens:** The HTTP gateway accepted structured bearer tokens (`operator:<id>`, `approver:<id>`, `agent:<id>`) as pre-authenticated, completely bypassing the configured server authentication secret (`--auth-token` / `expected_token`). An unauthenticated attacker sending `Authorization: Bearer operator:attacker` received full `AUTHENTICATED_OPERATOR` privileges with wildcard scopes (`*`).
2. **Caller-Supplied Delegation Authority Forgery:** A caller could assert arbitrary parent identities via HTTP headers (`X-Actentra-Delegated-By`, `X-Actentra-Parent`) or JSON body attributes. The gateway directly appended the claimed parent identity to the caller's `allowed_agents` without validating any server-side delegation grant or delegator consent.

This second remediation establishes strict trust boundaries:
- **Zero Authentication Bypass:** Structured tokens never independently authenticate a caller when a secret or token principals are configured. Unmatched credentials fail closed with HTTP 401 Unauthorized.
- **Cryptographic / Server-Side Delegation Grants:** Delegation requires an explicit `DelegationGrant` in a thread-safe `DelegationRegistry`. Caller-supplied delegation headers without a registered, active, unexpired, and non-revoked grant are strictly rejected with `IdentitySecurityError` (HTTP 403).
- **Strict Scope and Authority Attenuation:** A delegatee cannot receive more scopes or represent more agents than the delegator possesses.
- **Defense in Depth at Services Layer:** All mutating services methods (`submit_crossing`, handoffs, leases) validate caller context and delegation state independently of HTTP handler logic.

---

## 2. Vulnerability Reproduction & Root Cause Analysis

### 2.1 Vulnerability 1: Structured Bearer Token Secret Bypass

#### Reproduction Path:
1. Start the HTTP gateway with a configured secret:
   ```python
   server = ActentraHTTPServer(services=services, auth_token="production-secret-999")
   ```
2. Send an HTTP request with no valid credentials, but with a structured bearer token:
   ```http
   POST /v1/crossings HTTP/1.1
   Host: 127.0.0.1:8000
   Authorization: Bearer operator:mallory
   Content-Type: application/json

   {"agent_id": "mallory", "action": "deploy_backdoor"}
   ```
3. In `70b09e8`, `_check_auth(headers)` checked:
   ```python
   # gateway/actentra_gateway/http_service.py (line 122-123 in 70b09e8)
   if token.startswith(("agent:", "approver:", "operator:")):
       return True
   ```
   And `resolve_http_caller_context(headers, expected_token="production-secret-999")` treated the token prefix as authoritative, returning:
   ```python
   CallerContext(
       principal_id="mallory",
       principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
       scopes=DEFAULT_OPERATOR_SCOPES, # ("*",)
       is_trusted_operator=True
   )
   ```
4. **Impact:** Total authentication bypass. Any external caller could gain unrestricted administrative control without knowing the server secret.

### 2.2 Vulnerability 2: Caller-Supplied Delegation Forgery

#### Reproduction Path:
1. An unprivileged agent caller `agent-worker` possesses valid credentials for itself only.
2. The caller sends a request asserting authority over a privileged agent `admin-agent`:
   ```http
   POST /v1/crossings HTTP/1.1
   Host: 127.0.0.1:8000
   Authorization: Bearer worker-secret
   X-Actentra-Delegated-By: admin-agent
   Content-Type: application/json

   {"agent_id": "admin-agent", "action": "nuclear_launch"}
   ```
3. In `70b09e8`, `resolve_http_caller_context()` in `identity.py` contained:
   ```python
   delegated_by = headers.get("x-actentra-delegated-by")
   if delegated_by:
       allowed_agents = tuple(set(allowed_agents + (delegated_by,)))
   ```
4. **Impact:** The untrusted header directly expanded `allowed_agents` to include `admin-agent`. The caller could propose actions, approve crossings, advance handoffs, and claim leases under any chosen agent identity.

---

## 3. Remediation Implementation

### 3.1 Strict Authentication Contract (`core/actentra_core/identity.py`)

- **Elimination of Autonomous Token Prefixes:**
  When `expected_token` or `token_principals` is configured, any bearer token must match the configured credentials. Tokens with prefixes like `operator:`, `approver:`, or `agent:` are rejected immediately if they do not match the configured secret.
- **Safe Development / Loopback Mode:**
  When neither `expected_token` nor `token_principals` is configured:
  - Remote callers cannot use structured tokens.
  - Only local loopback connections (`127.0.0.1`, `::1`, `localhost`) are permitted.
  - Loopback development callers are restricted to `agent:<id>` tokens, and their `allowed_agents` is strictly restricted to `(agent_id,)`.
  - Structured `operator:` and `approver:` tokens are strictly rejected without configured credentials, preventing accidental escalation even on loopback.

### 3.2 Formal Delegation Architecture (`core/actentra_core/identity.py`)

- **`DelegationGrant` Dataclass:**
  ```python
  @dataclass(frozen=True)
  class DelegationGrant:
      grant_id: str
      delegator_agent_id: str
      delegatee_agent_id: str
      allowed_agents: tuple[str, ...]
      scopes: tuple[str, ...]
      is_revoked: bool = False
      expires_at: float | None = None
      created_at: float = field(default_factory=time.time)
  ```
- **Thread-Safe `DelegationRegistry`:**
  - Manages active delegation grants with monotonic revocation.
  - Enforces scope attenuation:
    $$\text{delegatee\_scopes} \subseteq \text{delegator\_scopes}$$
    $$\text{delegatee\_allowed\_agents} \subseteq \text{delegator\_allowed\_agents}$$
  - Direct helper `register_grant_direct()` ensures registered grants are immediately queryable and auditable.
- **Reconciliation in `resolve_http_caller_context`:**
  - When dynamic delegation headers (`X-Actentra-Delegated-By`, `X-Actentra-Parent`, `X-Actentra-Delegation-Grant`) are supplied:
    1. The delegator and grant ID are looked up in the `DelegationRegistry`.
    2. If no valid, active, unexpired grant exists matching delegatee and delegator, `IdentitySecurityError` is raised.
    3. If valid, the child's `allowed_agents` is restricted strictly to the grant's `allowed_agents`, and scopes are restricted to the intersection of the caller's scopes and the grant's scopes.

### 3.3 Gateway Endpoint Enforcement (`gateway/actentra_gateway/http_service.py`)

- **Authentication Gate (`_check_auth`):**
  Removed prefix-based auth bypass entirely:
  ```python
  def _check_auth(self, headers: dict[str, str]) -> bool:
      if not self.auth_token and not self.token_principals:
          return True
      token = self._extract_token(headers)
      if not token:
          return False
      if self.auth_token and hmac.compare_digest(token, self.auth_token):
          return True
      if self.token_principals and token in self.token_principals:
          return True
      return False
  ```
  Unauthenticated requests are blocked at the transport layer with HTTP 401 Unauthorized.
- **Delegation Management Endpoints:**
  - `POST /v1/delegations`: Authenticated delegators can register explicit delegation grants.
  - `GET /v1/delegations/{id}`: Inspect grant details and validity.
  - `DELETE /v1/delegations/{id}`: Revoke active delegation grants.

### 3.4 Services Layer Enforcement (`gateway/actentra_gateway/services.py`)

- **`_validate_caller_context()`**:
  - Independent service-layer validation of caller context, principal type, and delegation provenance.
  - Detects and rejects forged delegation, expired grants, and revoked grants.
- **Enforcement on All Mutations:**
  - `submit_crossing()`: Rejects caller-supplied JSON fields (`parent_agent_id`, `delegated_by`, `parent`) attempting to forge authority. Enforces that `crossing.agent_id` is authorized by `caller_context.is_agent_allowed()`.
  - `create_task_handoff()`, `advance_task_handoff()`, `verify_task_handoff()`: Validates handoff actor authorization against active delegation.
  - `acquire_resource_lease()`, `release_resource_lease()`: Validates owner authorization.

---

## 4. Adversarial Regression Test Suite

All 14 required adversarial test scenarios were implemented in `tests/unit/test_security_finding_01_identity.py`:

| # | Test Name | Attack Scenario | Result |
|---|---|---|---|
| 1 | `test_adversarial_structured_agent_token_without_configured_secret` | Caller sends `Bearer agent:agent-1` without server secret | HTTP 401 Unauthorized |
| 2 | `test_adversarial_structured_operator_token_without_configured_secret` | Attacker sends `Bearer operator:admin` to bypass secret | HTTP 401 Unauthorized |
| 3 | `test_adversarial_structured_approver_token_without_configured_secret` | Attacker sends `Bearer approver:judge` to bypass secret | HTTP 401 Unauthorized |
| 4 | `test_adversarial_valid_configured_secret_with_bound_principal` | Authorized client sends valid secret with bound principal | HTTP 200 OK |
| 5 | `test_adversarial_invalid_configured_secret` | Caller sends wrong bearer secret | HTTP 401 Unauthorized |
| 6 | `test_adversarial_missing_authentication` | Caller sends no Authorization header | HTTP 401 Unauthorized |
| 7 | `test_adversarial_caller_supplied_parent_identity` | Caller supplies `X-Actentra-Parent` without registered grant | HTTP 403 Forbidden |
| 8 | `test_adversarial_caller_supplied_delegated_by_identity` | Caller supplies `X-Actentra-Delegated-By` without registered grant | HTTP 403 Forbidden |
| 9 | `test_adversarial_child_attempting_to_exceed_parent_scopes` | Delegation grant requests scopes parent does not possess | Rejected with ValueError (attenuation violation) |
| 10 | `test_adversarial_child_attempting_to_represent_unauthorized_agent` | Delegation grant requests agent parent cannot represent | Rejected with ValueError (attenuation violation) |
| 11 | `test_adversarial_revoked_or_invalid_delegation` | Caller attempts to use revoked or expired delegation grant | HTTP 403 Forbidden |
| 12 | `test_adversarial_legitimate_authorized_delegation` | Delegator registers valid grant; child advances handoff | HTTP 200 OK |
| 13 | `test_adversarial_direct_services_layer_delegation_forgery` | Service invoked directly with forged caller context / JSON | Rejected at service layer with `IdentitySecurityError` |
| 14 | `test_adversarial_concurrent_identity_and_delegation_isolation` | 20 concurrent threads mixing authorized and forged calls | Zero cross-thread context contamination |

---

## 5. Verification Results

### 5.1 Test Suites

- **Finding 01 Test Suite (24 tests):**
  ```bash
  uv run pytest tests/unit/test_security_finding_01_identity.py
  # 24 passed in 1.36s
  ```
- **All Security Finding Suites (90 tests):**
  ```bash
  uv run pytest tests/unit/test_security_finding_01_identity.py \
                 tests/unit/test_security_finding_02_dns_rebinding.py \
                 tests/unit/test_security_finding_03_warrant_quotas.py \
                 tests/unit/test_security_finding_04_postconditions.py \
                 tests/unit/test_security_finding_05_external_outcomes.py \
                 tests/unit/test_security_review_remediations.py
  # 90 passed in 22.34s
  ```
- **Full Fast Test Suite:**
  ```bash
  uv run pytest -m "not slow" -o addopts= -q
  # 239 passed, 4 skipped in 41.80s
  ```

### 5.2 Linting and Type Checking

- **Ruff:**
  ```bash
  uv run ruff check core executors gateway sdk cli tests
  # All checks passed!
  ```
- **Mypy:**
  ```bash
  uv run mypy
  # Success: no issues found in 38 source files
  ```

---

## 6. Trust Model & Remaining Limitations

1. **In-Memory Delegation Registry vs. Distributed Stores:**
   The current `DelegationRegistry` maintains grants in-memory within the gateway process. In a distributed multi-node deployment, grants should be backed by a persistent store (e.g. SQLite/PostgreSQL) or signed via cryptographic capability tokens (e.g., Macaroons, Biscuits, or signed JWT delegation chains).
2. **Local Loopback Developer Convenience:**
   When running locally without `--auth-token` or `token_principals`, loopback clients on `127.0.0.1` may use `agent:<id>` tokens to simulate local multi-agent communication. This mode is restricted to loopback and strictly rejects `operator:` / `approver:` escalation. Production deployments must always provide an authentication secret.
