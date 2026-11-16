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
  1. `receipts` table: Append-only hash chain of decision and outcome records (`seq`, `crossing_id`, `session_id`, `canonical_hash`, `policy_version`, `verdict`/`status`, `result_hash`, `error`, `prev_hash`, `entry_hash`).
  2. `action_envelopes` table: Full canonical action envelope JSON indexed by `crossing_id`.
  3. `pending_approvals` table: Human approval requests (`crossing_id`, `session_id`, `canonical_hash`, `tool`, `verb`, `resource`, `params`, `risk_tags`, `status`, `expires_at`, `resolution_ts`). Survives in `pending`, `approved`, `rejected`, `expired`, or `consumed` status.
- **Process-Local State (reset upon process restart):**
  1. `Boundary` session taint tracking (`_session_taints` dictionary).
  2. In-memory policy rate-limit token buckets (`RateLimiter._buckets`).
  3. Cumulative session budget counters (`BudgetTracker._usage`).
  4. Emergency freeze state (`PolicyEngine._frozen`).
  5. Cryptographic capability warrant in-memory quota tracking (`WarrantRegistry._use_counts`).

### 3.2 Identity & Provenance Authority

1. **Caller-Asserted Identity:** Over the local HTTP gateway (`/v1/crossings`), caller-supplied `session_id`, `agent_id`, and declared `provenance` are **caller assertions**, not authenticated principals.
2. **Untrusted Declaration Boundary:** An agent model or untrusted remote caller must never be permitted to authorize itself or elevate its trust classification via self-declared provenance.
3. **Trusted Integration Harness:** In multi-agent or production workflows, principal identity and session bindings must be injected by the trusted integration wrapper (e.g., authenticated proxy, server-side harness, or DPAPI credentials), not extracted from untrusted model outputs.
4. **Envelope Action Hash Scope:** The canonical action hash binds `envelope_version`, `session_id`, `agent_id`, and the canonical `ActionSpec`. It does not cover unstructured intent or subjective claims.

### 3.3 Outcome Evidence Classes

Actentra categorizes outcomes into two strictly distinct evidential tiers:

1. **Executor-Observed Outcome (`reported_by: None` / first-party):**
   - Dispatched through Actentra's registered scoped executors (`LocalFSExecutor`, `ScopedSQLiteExecutor`, `ScopedHTTPExecutor`).
   - The executor runs within the local boundary and computes the result hash directly from execution return data before recording the outcome receipt.
2. **Caller-Reported Outcome (`reported_by: "caller"`):**
   - For externally managed executions, recorded via `POST /v1/crossings/{id}/outcome`.
   - The receipt explicitly records `reason: "caller-reported"` and returns `reported_by: "caller"`.
   - **Crucial Distinction:** A caller-reported outcome receipt proves that an external agent reported an outcome to Actentra; it does **not** constitute independent proof of real-world state or proof that a remote system performed the requested effect.

### 3.4 Restart, Crash, and Recovery Semantics

1. **Startup Approval Cleanup:** On startup, `AppServices` calls `ReceiptStore.recover_pending_approvals()`, which transitions any pending or approved records whose TTL has elapsed to `'expired'`. Unexpired pending and approved crossings remain intact and executable.
2. **Crash Recovery Distinction:** Crossings that were authorized but never dispatched must not be blindly recovered as `unknown`, because decision-only crossings may intentionally await external caller reporting. Only crossings where execution dispatch was actively in flight when the process terminated should be marked `unknown` upon restart.
3. **Atomic Execution Claims:** Transitioning an approved crossing from `'approved'` to `'consumed'` is performed atomically in SQLite WAL via `claim_approval_for_execution()` with `BEGIN IMMEDIATE`. Concurrent or duplicate execute requests fail closed.
4. **Local Hash Chain Boundary:** The SQLite SHA-256 hash chain provides tamper evidence against accidental edits and uncoordinated modifications. It does not defend against a hostile root administrator capable of rewriting the database unless anchored to an independently stored, signed Ed25519 checkpoint.

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
  - If `execute: true` is passed and the action is allowed (or once approved), gateway dispatches directly to registered executors (`LocalFSExecutor`, `ScopedSQLiteExecutor`, `ScopedHTTPExecutor`), commits outcome receipt, and returns the result.
  - If execution is managed externally, the client uses `POST /v1/crossings/{id}/outcome` to record the post-execution outcome receipt (`success`, `failure`, `unknown`), completing the audit chain.
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
