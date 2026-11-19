# Remediation Report: Finding 01 — Caller-Asserted Agent Identity and Unauthorized Delegation

**Audit Commit:** `02887cd`  
**Finding ID:** F-1 (Enterprise Security Audit)  
**Severity:** HIGH  
**Status:** REMEDIATED  
**Date:** 2026-11-19  

---

## 1. Executive Summary

During the independent enterprise security audit of Actentra, Finding 01 identified that caller identities across the REST gateway and services layer were asserted via caller-controlled JSON request bodies and unverified HTTP headers rather than cryptographically bound to authenticated principals. This allowed any client with network access or a shared bearer token to impersonate arbitrary agents, forge task handoffs, prematurely verify work, acquire or release resource leases belonging to other agents, and escalate privileges.

This remediation establishes an authenticated principal architecture, enforces role-based permission scopes, restricts identity assertions to explicitly allowed principals or delegations, mandates lease ownership verification on release, and prevents privilege escalation across all gateway endpoints.

---

## 2. Vulnerability Reproduction & Root Cause Analysis

### 2.1 Affected Files and Lines

- `gateway/actentra_gateway/http_service.py:623-685, 748-792`: Extracted `agent_id`, `caller_agent_id`, `verifier_agent_id`, and `owner_agent_id` directly from untrusted JSON payloads without reconciling them against bearer tokens or transport identity.
- `gateway/actentra_gateway/services.py:161-177`: Accepted arbitrary caller-asserted `agent_id` strings and evaluated policy decisions without validating principal authorization.
- `core/actentra_core/identity.py:54-129`: `CallerContext` lacked principal role hierarchies, granular permission scopes, and delegation validation.
- `core/actentra_core/receipts.py:2304-2328`: `release_lease()` permitted `owner_agent_id=None`, allowing any caller to release any active lease if they knew or guessed the `lease_id`.

### 2.2 Attack Vectors Confirmed

1. **Crossing Identity Spoofing**: An authenticated agent `attacker-agent` could propose actions asserting `agent_id: "victim-agent"`, generating receipts and executing actions under the victim's authority.
2. **Unauthorized Handoff Advancement & Verification**: An attacker could advance a handoff assigned to `agent-builder` by providing `caller_agent_id: "agent-builder"`, or verify incomplete handoffs by claiming `verifier_agent_id: "agent-auditor"`.
3. **Lease Denial of Service & Hijacking**: An attacker could acquire leases on shared resources on behalf of victims (`owner_agent_id: "victim"`), or release any agent's active lease by sending a release request with `owner_agent_id` omitted.
4. **Approval & Administrative Privilege Escalation**: Regular agents could call `/v1/crossings/{id}/approve` or `/v1/freeze` / `/v1/unfreeze`, taking over administrative and human approver roles.

---

## 3. Remediation Architecture & Implementation

### 3.1 Principal Hierarchy & Scopes (`core/actentra_core/identity.py`)

- **Granular Principal Types**: Added `AUTHENTICATED_AGENT`, `HUMAN_APPROVER`, `AUTHENTICATED_OPERATOR`, `LOCAL_PROCESS`, `UNAUTHENTICATED_CALLER`, `DELEGATED_AGENT`, and `EXECUTOR`.
- **Role Permission Scopes**: Defined standardized capability scopes:
  - `DEFAULT_AGENT_SCOPES`: `crossings:propose`, `crossings:execute`, `crossings:read`, `handoffs:create`, `handoffs:advance`, `handoffs:verify`, `leases:acquire`, `leases:release`.
  - `DEFAULT_APPROVER_SCOPES`: `crossings:read`, `crossings:approve`, `receipts:read`.
  - `DEFAULT_OPERATOR_SCOPES`: `*` (full administrative authority).
  - `DEFAULT_LOOPBACK_SCOPES`: Scoped for local developer loopback operation.
- **Enhanced `CallerContext`**:
  - `allowed_agents: tuple[str, ...]`: Whitelist of agent IDs this authenticated principal can act as.
  - `delegated_by: str | None`: Authenticated delegating principal for hierarchical subagent handoffs.
  - `has_scope(scope: str) -> bool`: Verifies permission scopes before executing operations.
  - `is_agent_allowed(agent_id: str) -> bool`: Validates authority to assert a given agent identifier.
  - `bound_agent_id(requested_agent: str | None) -> str`: Automatically binds omitted agent IDs to the authenticated principal.
  - `is_approver`: Read-only property ensuring only authenticated human approvers and operators can resolve approvals.
- **Header & Token Reconciliation**:
  - Structured credentials supported out of the box: `agent:<id>`, `approver:<id>`, `operator:<id>`.
  - Configurable `token_principals` mapping for per-agent bearer tokens.
  - `X-Actentra-Identity` headers conflicting with authenticated token identity are rejected immediately with `IdentitySecurityError`.

### 3.2 Services Layer Binding (`gateway/actentra_gateway/services.py`)

- Added `caller_context: CallerContext | None` parameter across all mutating operations:
  - `submit_crossing`: Validates `is_agent_allowed(agent_id_claim)` and checks `crossings:propose` / `crossings:execute` scopes.
  - `resolve_approval`: Requires `caller_context.is_approver` and `crossings:approve` scope.
  - `create_task_handoff`: Requires `handoffs:create` scope and authorization over `initiator_agent_id`.
  - `advance_task_handoff`: Requires `handoffs:advance` scope and verifies caller is assigned agent or authorized delegate.
  - `verify_task_handoff`: Requires `handoffs:verify` scope and verifies caller is designated verifier agent.
  - `acquire_resource_lease`: Requires `leases:acquire` scope and authorization over `owner_agent_id`.
  - `release_resource_lease`: Requires `leases:release` scope and matching `owner_agent_id`.

### 3.3 Gateway Endpoint Enforcement (`gateway/actentra_gateway/http_service.py`)

- Implemented centralized `_get_caller_context()` resolving authenticated credentials on every request.
- Added scope and identity enforcement to:
  - `POST /v1/crossings`: Rejects unauthorized identity claims with HTTP 403 `unauthorized_principal`.
  - `POST /v1/crossings/{id}/approve`: Rejects non-approver principals with HTTP 403 `forbidden`.
  - `POST /v1/crossings/{id}/execute`: Requires `crossings:execute` scope.
  - `POST /v1/handoffs`: Rejects unauthorized `initiator_agent_id` assertions.
  - `POST /v1/handoffs/{id}/advance`: Rejects unauthorized callers with HTTP 403.
  - `POST /v1/handoffs/{id}/verify`: Rejects unauthorized verifiers with HTTP 403.
  - `POST /v1/leases`: Rejects lease acquisition for other agents.
  - `POST /v1/leases/{id}/release`: Requires `owner_agent_id` in request body matching lease owner; returns HTTP 400 if omitted, HTTP 403 if unauthorized.
  - `POST /v1/freeze` and `POST /v1/unfreeze`: Restricted strictly to `AUTHENTICATED_OPERATOR` / `is_trusted_operator`.

### 3.4 Durable Storage Hardening (`core/actentra_core/receipts.py`)

- In `ReceiptStore.release_lease()`: strictly mandates non-blank `owner_agent_id`. If `owner_agent_id` is `None`, empty, or does not match the active lease record, the release operation returns `False` and leaves the lease active.

---

## 4. Proof of Remediation

### 4.1 Security Regression Test Suite

A dedicated regression test suite was implemented in `tests/unit/test_security_finding_01_identity.py`, containing 10 automated test cases:

| Test Case | Scenario Tested | Outcome |
|---|---|---|
| `test_crossing_identity_spoofing_rejected` | Authenticated agent asserts victim agent ID in `/v1/crossings` | HTTP 403 `unauthorized_principal` |
| `test_header_identity_spoofing_rejected` | Caller token conflicts with `X-Actentra-Identity` header | HTTP 403 `unauthorized_principal` |
| `test_operator_privilege_spoofing_via_headers_rejected` | Untrusted caller sends headers asserting operator/approver roles | Headers ignored; privileges denied |
| `test_unauthorized_handoff_advance_rejected` | Attacker attempts to advance handoff assigned to builder | HTTP 403 Forbidden |
| `test_unauthorized_handoff_verify_rejected` | Attacker attempts to verify handoff designated for auditor | HTTP 403 Forbidden |
| `test_delegated_authority_succeeds` | Subagent with verified delegation advances handoff for parent agent | HTTP 200 OK |
| `test_unauthorized_lease_release_and_missing_owner_rejected` | Attacker attempts lease release with omitted or victim owner ID | HTTP 400 / 403; lease remains active |
| `test_unauthorized_lease_acquisition_rejected` | Attacker attempts to acquire lease under victim ID | HTTP 403 `unauthorized_principal` |
| `test_privilege_escalation_approvals_and_freeze_rejected` | Normal agent attempts crossing approval and freeze endpoints | HTTP 403 Forbidden |
| `test_concurrent_requests_preserve_identity_isolation` | 10 concurrent threads make simultaneous authorized and spoofed requests | Zero identity leakage; all validations hold |

### 4.2 Verification Results

- **Unit & Security Tests**: All 10 security regression tests pass:
  ```
  tests/unit/test_security_finding_01_identity.py .......... [100%]
  10 passed in 0.95s
  ```
- **Full Test Suite**: All 179 fast tests across Actentra pass without any regressions:
  ```
  uv run pytest -m "not slow" -q
  100% passed
  ```
- **Linting & Code Quality**:
  ```
  uv run ruff check core executors gateway sdk cli tests
  All checks passed!
  ```
- **Type Safety**:
  ```
  uv run mypy
  Success: no issues found in 37 source files
  ```

---

## 5. Trust Model & Remaining Limitations

### 5.1 Authenticated vs. Caller-Provided Metadata

| Identity Attribute | Source | Authenticated? | Authority Granted |
|---|---|---|---|
| Principal ID | Authorization Bearer Token | Yes | Grants access only to scoped operations for that principal |
| Principal Type | Server Token Configuration | Yes | Differentiates Agent, Human Approver, Operator, and Local Process |
| Allowed Agents | Server Token Configuration | Yes | Whitelist of agent IDs the principal can represent |
| Delegated By | Server Token Configuration | Yes | Explicit subagent delegation provenance |
| `X-Actentra-Identity` | HTTP Request Header | No (Metadata) | Display only; must match authenticated token or request is rejected |
| JSON `agent_id` | HTTP Request Body | No (Metadata) | Validated against `allowed_agents`; cannot spoof arbitrary agents |
| JSON `owner_agent_id` | HTTP Request Body | No (Metadata) | Validated against `allowed_agents` and database record |

### 5.2 Remaining Architectural Limitations

1. **Static Bearer Credentials**: The gateway currently validates bearer tokens against in-memory configuration or prefix patterns. Distributed multi-cluster enterprise deployments require short-lived cryptographic tokens (OIDC JWTs, SPIFFE x509-SVIDs, or mTLS peer certificates).
2. **Process-Local State**: While identity validation is bound per-request, rate-limiting buckets and unfreeze mechanisms remain process-local until distributed state synchronization is introduced.
3. **Local Loopback Mode**: When run locally without an authentication token configured (developer CLI mode), loopback callers on `127.0.0.1` are permitted to execute local operations. Production environments exposed to non-loopback networks require `--auth-token` or `token_principals` configuration.
