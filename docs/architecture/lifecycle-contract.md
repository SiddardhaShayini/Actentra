# Actentra V2 — Action Lifecycle & Operational Contract

**Status:** Normative Specification  
**Version:** 2.0.0  
**Date:** 2026-11-13  

---

## 1. Overview & Purpose

Actentra is a local-first, deterministic execution boundary for AI-agent tool actions.
This document defines the **single normative lifecycle contract** governing how tool calls are proposed, canonicalized, evaluated, approved, dispatched, executed, and recorded across all Actentra integrations:
1. In-process Python SDK (`Boundary.execute()`, `@guard`)
2. Model Context Protocol (MCP) Stdio Proxy (`MCPStdioProxy`)
3. Local HTTP Gateway Service (`/v1/crossings`)

---

## 2. The Unified Action Lifecycle

Every supported integration path adheres to the following linear lifecycle:

```text
    [Agent / Caller Proposes Action]
                   │
                   ▼
    1. Canonicalization & Hash Binding
       - Tool, verb, resource normalization (strict Windows/POSIX rules)
       - Canonical JSON parameter canonicalization
       - Crockford ULID crossing_id generation
       - SHA-256 canonical_hash computation
                   │
                   ▼
    2. Deterministic Policy Evaluation
       - Deny-overrides YAML rule evaluation
       - Dynamic risk tag calculation
       - Cumulative session budget & rate limit check
       - Session taint propagation check
                   │
                   ▼
       [What is the verdict?]
       ├── DENY / HOLD ─────────────► [Record Decision Receipt] ──► Abort (Fail Closed)
       ├── ASK ─────────────────────► [Record Decision Receipt]
       │                                     │
       │                                     ▼
       │                              [Persist Pending Approval]
       │                                     │
       │                              (Human Operator Review)
       │                               ├── Approved ──► [Record Approval Grant]
       │                               └── Rejected / Expired ──► Abort
       └── ALLOW / ALLOW_CONSTRAINTS
                   │
                   ▼
    3. Pre-Execution Decision Durability (Invariant I5)
       - Append-only SQLite WAL decision receipt committed before any execution
                   │
                   ▼
    4. Execution Gate & TOCTOU Verification (Invariant I3)
       - Action payload hash recomputed immediately before execution
       - Hash must strictly match decision.canonical_hash
                   │
                   ▼
    5. Scoped Dispatch / Execution
       - Executed strictly by registered executor (FS, SQLite, HTTP, or user callable)
       - Constraints injected (read_only, max_bytes, allowed_hosts, etc.)
                   │
                   ▼
    6. Post-Execution Outcome Receipt (Invariant I5)
       - Append-only SQLite WAL outcome receipt committed:
         * "success" with result hash
         * "failure" with redacted error label
         * "unknown" on crash / interruption recovery
```

---

## 3. Crossing States & Transitions

| State | Description | Next Valid States |
| --- | --- | --- |
| `PROPOSED` | Action submitted by agent or caller. | `EVALUATED`, `INVALID` |
| `INVALID` | Canonicalization or envelope validation failed. | `HOLD` (terminal) |
| `EVALUATED` | Deterministic engine produced a verdict (`ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `DENY`, `HOLD`, `ASK`). | `PENDING_APPROVAL`, `RECORDING_DECISION`, `TERMINATED` |
| `PENDING_APPROVAL` | Verdict was `ASK`. Awaiting human operator resolution. Persisted in SQLite WAL. | `APPROVED`, `REJECTED`, `EXPIRED` |
| `APPROVED` | Operator approved the exact `canonical_hash`. Survives gateway restarts. | `CONSUMED` (dispatch started), `EXPIRED` |
| `REJECTED` | Operator rejected the pending action. | `TERMINATED` (terminal) |
| `EXPIRED` | Pending approval TTL elapsed without resolution. | `TERMINATED` (terminal) |
| `CONSUMED` | Approval grant atomically claimed for execution. Prevents concurrent duplicates. | `EXECUTING`, `OUTCOME_UNKNOWN` |
| `RECORDING_DECISION` | Committing decision receipt to SQLite WAL hash chain. | `EXECUTING`, `TERMINATED` |
| `EXECUTING` | Action actively running in registered scoped executor or caller callable. | `COMPLETED_SUCCESS`, `COMPLETED_FAILURE`, `OUTCOME_UNKNOWN` |
| `COMPLETED_SUCCESS` | Execution succeeded; result digest/hash recorded in outcome receipt. | `TERMINATED` (terminal) |
| `COMPLETED_FAILURE` | Execution failed with error; redacted error label recorded. | `TERMINATED` (terminal) |
| `OUTCOME_UNKNOWN` | Process terminated during in-flight execution; recovered as `unknown`. | `TERMINATED` (terminal) |

### 3.1 Persistence Scope vs. Process-Local State

Actentra maintains a strict boundary between what is durable across restarts and what is process-local:

- **Persisted in SQLite WAL (survives restart & power cycle):**
  1. `receipts` table: Append-only hash chain of decision and outcome records (`seq`, `crossing_id`, `session_id`, `canonical_hash`, `policy_version`, `verdict`/`status`, `result_hash`, `error`, `evidence_status`, `prev_hash`, `entry_hash`).
  2. `action_envelopes` table: Full canonical action envelope JSON indexed by `crossing_id`.
  3. `pending_approvals` table: Human approval requests (`crossing_id`, `session_id`, `canonical_hash`, `tool`, `verb`, `resource`, `params`, `risk_tags`, `status`, `expires_at`, `resolution_ts`). Survives in `pending`, `approved`, `rejected`, `expired`, or `consumed` status.
  4. `session_budgets` table: Durable cumulative session counters (`actions_count`, `external_calls_count`, `write_bytes_count`, `updated_at`) surviving process restarts.
  5. `session_taints` table: Durable session taint level (`trusted`, `untrusted`, `unknown`) surviving process restarts.
  6. `evidence_records` table: Cryptographically hashed evidential observation records binding crossings to verification tiers.
  7. `resource_leases` table: Durable multi-agent coordination leases (`lease_id`, `resource`, `owner_agent_id`, `session_id`, `mode`, `status`, `expires_at`, `lease_hash`).
  8. `warrant_usages` table: Durable capability warrant quota consumption counters (`warrant_id`, `issuer`, `holder`, `max_uses`, `consumed_uses`, `expires_at`, `created_at`, `updated_at`).
- **Process-Local State (reset upon process restart):**
  1. In-memory policy rate-limit token buckets (`RateLimiter._buckets`).
  2. Emergency freeze state (`PolicyEngine._frozen`).
  3. Standalone in-memory warrant cache fallback (when `ReceiptStore` is not attached). Active and exhausted finite-use quotas are non-evictable to prevent replay.

### 3.2 Identity & Provenance Authority

1. **Principal Types & Caller Context:** Actentra validates all incoming callers via `CallerContext` and `PrincipalType`:
   - `LOCAL_PROCESS`: Direct in-process or loopback caller without token auth (untrusted agent default, trusted operator if explicitly configured).
   - `AUTHENTICATED_OPERATOR`: Bearer token authenticated operator.
   - `UNAUTHENTICATED_CALLER`: Remote or unverified HTTP caller.
   - `DELEGATED_AGENT`: Downstream AI agent acting on behalf of a principal.
2. **Untrusted Declaration Boundary:** An unauthenticated caller or agent model cannot claim reserved system or admin identities, and cannot self-declare `trusted` provenance to bypass taint rules. Attempts fail closed (`403 Forbidden` / `IdentitySecurityError`).
3. **Trusted Integration Harness:** In multi-agent or production workflows, principal identity and session bindings must be injected by the trusted integration wrapper (e.g., authenticated proxy, server-side harness, or DPAPI credentials), not extracted from untrusted model outputs.
4. **Envelope Action Hash Scope:** The canonical action hash binds `envelope_version`, `session_id`, `agent_id`, and the canonical `ActionSpec`. It does not cover unstructured intent or subjective claims.

### 3.3 Evidence Quality Taxonomy & Tiers

Actentra classifies evidence into 5 formal tiers (`spec/evidence.v1.schema.json`, `EvidenceRecord`):

1. **`locally_observed` (First-Party Execution):**
   - Dispatched through Actentra's registered scoped executors (`LocalFSExecutor`, `ScopedSQLiteExecutor`, `ScopedHTTPExecutor`).
   - The executor runs within the local boundary and computes the result hash directly from execution return data before recording the outcome receipt.
2. **`caller_reported` (External Agent Claims):**
   - For externally managed executions, recorded via `POST /v1/crossings/{id}/outcome`.
   - The receipt explicitly records `reason: "caller-reported"` and `evidence_status: "caller_reported"`.
   - **Crucial Distinction:** A caller-reported outcome receipt proves that an external agent reported an outcome to Actentra; it does **not** constitute independent proof of real-world state or proof that a remote system performed the requested effect.
3. **`externally_verified` (Ground-Truth Observation):**
   - Corroborated by deterministic, out-of-band ground-truth probes (e.g. `ObservationRecord` file sha256 check matching claimed outcome).
4. **`stale`:**
   - Evidential claim whose TTL (`expires_at`) has elapsed.
5. **`unknown`:**
   - Default or crash-recovered evidence status when verification could not be performed or completed.

### 3.4 Restart, Crash, and Recovery Semantics

1. **Startup Approval Cleanup:** On startup, `AppServices` calls `ReceiptStore.recover_pending_approvals()`, which transitions any pending or approved records whose TTL has elapsed to `'expired'`. Unexpired pending and approved crossings remain intact and executable.
2. **Crash Recovery Distinction:** Crossings that were authorized but never dispatched must not be blindly recovered as `unknown`, because decision-only crossings may intentionally await external caller reporting. Only crossings where execution dispatch was actively in flight when the process terminated should be marked `unknown` upon restart.
3. **Atomic Execution Claims:** Transitioning an approved crossing from `'approved'` to `'consumed'` is performed atomically in SQLite WAL via `claim_approval_for_execution()` with `BEGIN IMMEDIATE`. Concurrent or duplicate execute requests fail closed.
4. **Local Hash Chain Boundary:** The SQLite SHA-256 hash chain provides tamper evidence against accidental edits and uncoordinated modifications. It does not defend against a hostile root administrator capable of rewriting the database unless anchored to an independently stored, signed Ed25519 checkpoint.

### 3.5 Multi-Agent Coordination & Resource Leases

1. **Durable Conflict Locking:** Agents coordinate operations on shared resources using explicit `ResourceLease` records stored in SQLite WAL (`spec/lease.v1.schema.json`).
2. **Exclusive vs. Shared Modes:** Mutating verbs (`write`, `delete`, `exec`, `admin`) require holding an exclusive lease or ensuring no active exclusive lease is held by another agent. Conflicting attempts fail closed with `Verdict.DENY` (`rule_id="coordination:resource-locked"`).
3. **Lease TTL & Automatic Expiry:** Leases carry explicit ISO-8601 expiration timestamps (`expires_at`). Expired leases do not block subsequent agents.
4. **Postcondition Verification:** When requested (`verify_postcondition=True`), successful mutations trigger automatic workspace observation via `WorkspaceFileVerifier`, recording `ObservationRecord` and generating an `externally_verified` `EvidenceRecord` linked to the crossing via causal DAG reference (`verifies`).

---

## 4. Integration Roles & Contracts

### 4.1 In-Process Python SDK (`Boundary`)
- **Propose & Evaluate:** `Boundary.execute()` canonicalizes input into `ActionEnvelope`, evaluates policy.
- **Approval:** If `verdict == ASK`, checks in-memory/durable approval grant or calls `approval_callback`.
- **Pre-execution receipt:** Writes `decision` receipt into `ReceiptStore`.
- **Execute:** Invokes user `fn(envelope, decision)` with parameter constraints.
- **Outcome receipt:** Writes `outcome` receipt (`success` or `failure`).

### 4.2 MCP Stdio Proxy (`MCPStdioProxy`)
- **Propose & Intercept:** Intercepts `tools/call` JSON-RPC requests over stdio without shell execution.
- **Pinning:** Hashes tool definitions from `tools/list` to detect runtime modifications (CVE-2025-54136 defense).
- **Enforcement:** Mediates calls through `Boundary.execute()`. Downstream MCP server only receives authorized calls.
- **Outcome:** Catches downstream JSON-RPC response and records outcome receipt.

### 4.3 Local HTTP Gateway Service (`/v1/crossings`)
- **Propose & Evaluate:** `POST /v1/crossings` canonicalizes envelope, evaluates policy, and records decision receipt.
- **Execution Continuation:**
  - If `execute: true` is passed and the action is allowed (or once approved), gateway dispatches through the authoritative execution lifecycle (`_dispatch_and_record`), enforcing:
    - TOCTOU hash verification immediately prior to dispatch.
    - Policy constraint and postcondition inspection (`require_postcondition`, `postcondition`, `expected_digest`).
    - Execution claim binding and registration.
    - Full lifecycle state machine advancement (`authorized` -> `claimed` -> `executing` -> `verification_pending` -> `succeeded`/`failed`/`unknown`).
    - Mandatory postcondition verification via configured verifier before success promotion; an executor returning success is NOT sufficient without verification.
    - Atomic outcome recording (`externally_verified` evidence upon verification, or `failure`/`unknown` if refuted or unverified).
  - If execution is managed externally, the client uses `POST /v1/crossings/{id}/claim` to obtain a one-time `ExecutionClaim`. When postcondition verification is required, `POST /v1/observations/verify` must generate a bound `ObservationRecord` anchored to a canonical `VerificationContext` (exact crossing, action hash, canonical resource, expected postcondition/digest, active claim, executor, and authenticated verifier). `POST /v1/crossings/{id}/outcome` atomically validates and consumes both the bound observation and execution claim before recording `success`, completing the audit chain.
- **Approval Persistence:** `ASK` crossings are persisted in SQLite WAL `pending_approvals`. Survives gateway restarts.
- **Operator Console:** Web UI at `/ui` exposes real-time approvals, simulator, policy linter, and paged receipts.

---

## 5. Local-Only Security Posture

1. **Loopback Default:** By default, Actentra HTTP Gateway binds strictly to loopback (`127.0.0.1` or `::1`).
2. **Remote Binding Gate:** Binding to `0.0.0.0` or any external interface requires:
   - Explicit CLI flag `--unsafe-allow-remote` or env `ACTENTRA_UNSAFE_ALLOW_REMOTE=1`.
   - Compulsory Bearer Token authentication (`ACTENTRA_GATEWAY_TOKEN`).
   - Requests without valid `Authorization: Bearer <token>` fail closed with 401 Unauthorized.
3. **CORS & Origin Hardening:** Wildcard `Access-Control-Allow-Origin: *` is strictly disallowed.
   - CORS is restricted to loopback origins (`http://127.0.0.1:<port>`, `http://localhost:<port>`).
   - Mutating routes (`POST`) require matching loopback origin or a trusted client header (`X-Actentra-Client`).
