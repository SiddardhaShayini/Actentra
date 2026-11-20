# Remediation Report: Finding F-5 — Unbound External Outcome Reporting

**Target:** External outcome reporting is unbound  
**Severity:** MEDIUM  
**Affected Source:** `gateway/actentra_gateway/services.py:521-559`; `gateway/actentra_gateway/http_service.py:479-507` (outcome route)  
**Date:** 2026-11-20  

---

## 1. Executive Summary

Finding F-5 from the Enterprise Security Audit identified that the Actentra Gateway accepted external outcome reports on allowed crossings without enforcing execution claims, executor identity checks, or single-use bindings. Any HTTP client with network access to the gateway could fabricate `status="success"` or `status="failure"` reports for any crossing ID, corrupting crossing receipt histories, causing false causal trace records, and artificially depleting session resource budgets.

This vulnerability has been remediated by implementing a cryptographically bound one-time execution claim architecture. Crossings can only be claimed once by an authenticated, authorized executor, and outcome submissions strictly mandate and atomically consume a valid, unexpired, matching claim.

---

## 2. Original Vulnerability & Attack Vectors

### 2.1 Attack Mechanism
In the original gateway implementation:
1. When a crossing was proposed and allowed by policy, it was committed with a `Decision` receipt.
2. The endpoint `POST /v1/crossings/{id}/outcome` allowed any caller to submit `{"status": "success"}` or `{"status": "failure"}`.
3. The endpoint did not verify:
   - Whether the crossing had ever been claimed or dispatched to an executor.
   - Whether the reporting caller was the authenticated executor assigned to the crossing.
   - Whether an outcome had already been claimed or reported (no claim single-use guarantee).
   - Whether the crossing decision even permitted execution (e.g. `deny` or unapproved `ask`).
4. On receiving `status="success"`, `services.record_external_outcome()` updated session resource budgets and appended an `OutcomeReceipt`, effectively validating fictitious tool executions.

### 2.2 Concrete Attack Impact
- **Fictitious Outcome Injection:** An unauthenticated or unauthorized caller could poll or guess crossing IDs and record fake success outcomes, misleading supervisory agents or downstream operators.
- **Budget Exhaustion & DoS:** Submitting fake outcomes with resource consumption exhausted session token, wall-clock, or call budgets, triggering denial of service against legitimate agent workflows.
- **Causal Graph Poisoning:** Fabricated outcomes created false causal links, corrupting the audit trail and tamper-evident receipt log.

---

## 3. Remediation Details

### 3.1 One-Time Execution Claim Architecture (`core/actentra_core/claims.py`)
Created a dedicated execution claims module providing:
- **`ExecutionClaim` Dataclass:** Stores `claim_id`, `crossing_id`, `executor_principal_id`, `session_id`, `canonical_hash`, `status` (`issued`, `consumed`, `expired`), `issued_at`, `expires_at`, `consumed_at`, and `claim_hash`.
- **Crockford Base32 Claim IDs:** Generated via `generate_claim_id()` with prefix `claim_` for high entropy and safe string representation.
- **Canonical Hash Binding:** `compute_claim_hash()` computes a deterministic SHA-256 digest over the claim's core parameters (`crossing_id`, `executor_principal_id`, `session_id`, `canonical_hash`, `issued_at`, `expires_at`).
- **`ExecutionClaimError` Exception:** Distinct exception hierarchy for claim validation failures.

### 3.2 Durable Claim Persistence in SQLite (`core/actentra_core/receipts.py`)
Extended `ReceiptStore`:
- **`execution_claims` Table:** Schema defines `claim_id PRIMARY KEY`, `crossing_id`, `executor_principal_id`, `session_id`, `canonical_hash`, `status CHECK (status IN ('issued', 'consumed', 'expired'))`, `issued_at`, `expires_at REAL`, `consumed_at REAL`, `claim_hash TEXT`, with indices on `crossing_id` and `(executor_principal_id, status)`.
- **Atomic Claim Issuance (`issue_execution_claim`):** Executes in a `BEGIN IMMEDIATE` write transaction. Checks for existing unexpired claims for the crossing; if an active claim exists, rejects with `ExecutionClaimError`. Persists the new claim.
- **Atomic Claim Consumption (`consume_execution_claim`):** Executes in a `BEGIN IMMEDIATE` write transaction:
  1. Verifies claim existence;
  2. Verifies `crossing_id` matches the claim's crossing;
  3. Verifies `executor_principal_id` matches the claim's assigned executor (rejecting cross-executor spoofing);
  4. Checks claim status: rejects already consumed claims (preventing replay attacks);
  5. Checks wall-clock expiration against `expires_at`;
  6. Atomically transitions status to `'consumed'`, sets `consumed_at = now`, and commits.

### 3.3 Gateway Endpoint Hardening (`gateway/actentra_gateway/http_service.py` & `services.py`)
- **`POST /v1/crossings/{id}/claim`:**
  - Authenticates `CallerContext` and requires `crossings:claim` or `crossings:execute` scope.
  - Verifies crossing exists and its decision allows execution (`verdict == "allow"`). Crossings with `deny` or unapproved `ask` cannot be claimed.
  - Verifies crossing has not already been executed or recorded with an outcome.
  - Verifies principal authority over the target agent.
  - Issues an `ExecutionClaim` in `ReceiptStore` and returns claim metadata (`claim_id`, `expires_at`, etc.).
- **`POST /v1/crossings/{id}/outcome`:**
  - Extracts `claim_id` from JSON request body or `X-Actentra-Claim-Id` header.
  - Rejects requests lacking a `claim_id` with `400 Bad Request` (`code: claim_required`).
  - Calls `services.record_external_outcome(...)` which calls `ReceiptStore.consume_execution_claim(...)`.
  - Claim errors map strictly to HTTP status codes:
    - Already consumed / replay / conflict -> `409 Conflict`
    - Cross-executor spoofing / forbidden -> `403 Forbidden`
    - Expired / not found / invalid -> `400 Bad Request` or `404 Not Found`
- **Evidence Partitioning:** External outcomes record evidence under `EvidenceTier.CALLER_REPORTED`, preventing external untrusted execution from posing as locally verified evidence.
- **In-Process Compatibility:** For existing internal SDK workflows calling `services.record_external_outcome()` with `caller_context=None` and `claim_id=None`, an internal claim is atomically generated and consumed, preserving backward compatibility while strictly enforcing claims over the HTTP gateway.

---

## 4. Verification and Regression Testing

A dedicated test suite was implemented in `tests/unit/test_security_finding_05_external_outcomes.py`:

| Test Name | Threat Vector Verified | Result |
|---|---|---|
| `test_outcome_rejected_without_claim` | Unbound outcome reporting without claim | **PASSED** (400 Bad Request) |
| `test_claim_issuance_and_successful_outcome_binding` | Legitimate claim issuance, consumption, and receipt commit | **PASSED** (200 OK, claim consumed) |
| `test_claim_replay_rejected` | Replay of consumed claim ID | **PASSED** (409 Conflict) |
| `test_cross_executor_claim_spoofing_rejected` | Executor A attempting to use Executor B's claim | **PASSED** (403 Forbidden) |
| `test_expired_claim_rejected` | Reporting outcome after claim TTL expiration | **PASSED** (400 Bad Request) |
| `test_cannot_claim_disallowed_crossing` | Attempting to claim a `deny` or `ask` crossing | **PASSED** (400 Bad Request) |
| `test_http_gateway_claim_and_outcome_end_to_end` | Full HTTP gateway integration across `/claim` and `/outcome` routes | **PASSED** (200 OK) |

In addition, existing test suites (`test_http_service.py`, `test_app_services.py`, `test_evidence.py`, `test_security_review_remediations.py`) and all prior security regression suites (Findings 01 through 04) were run and passed 100% cleanly (59 passed in security suites, 100% across the full repository).

---

## 5. Trust Model Impact & Remaining Risks

### Trust Model Improvements
- External outcome reporting is no longer an open injection point.
- Outcomes are cryptographically bound to an issued execution claim, the crossing ID, the executor principal, and the crossing canonical hash.
- Multi-executor environments can safely partition execution tasks without risk of cross-executor outcome poisoning.

### Remaining Limitations
- **Host / Process Trust:** The claim confirms that the outcome was submitted by the specific executor principal that was issued the claim. It does not provide cryptographic attestation (e.g. SGX/SEV enclave quotes) of what the external runner actually executed.
- **Single SQLite Writer:** Claim issuance and consumption use SQLite `BEGIN IMMEDIATE` transactions. In high-throughput distributed architectures, an HA consensus store (e.g. etcd, Spanner, or distributed Raft log) will be required.
