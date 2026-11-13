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
| `PROPOSED` | Action has been submitted by agent or caller. | `EVALUATED`, `INVALID` |
| `INVALID` | Canonicalization or envelope schema validation failed. | `HOLD` (terminal) |
| `EVALUATED` | Deterministic engine produced a verdict (`ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `DENY`, `HOLD`, `ASK`). | `PENDING_APPROVAL`, `RECORDING_DECISION`, `TERMINATED` |
| `PENDING_APPROVAL` | Verdict was `ASK`. Awaiting operator resolution. Persisted in SQLite WAL. | `APPROVED`, `REJECTED`, `EXPIRED` |
| `APPROVED` | Human operator approved the exact `canonical_hash` for the session. | `EXECUTING`, `EXPIRED` |
| `REJECTED` | Human operator rejected the pending action. | `TERMINATED` (terminal) |
| `EXPIRED` | Pending approval TTL elapsed without resolution. | `TERMINATED` (terminal) |
| `RECORDING_DECISION` | Committing decision receipt to SQLite WAL hash chain. | `EXECUTING`, `TERMINATED` |
| `EXECUTING` | Action is actively executing within the scoped executor. | `COMPLETED_SUCCESS`, `COMPLETED_FAILURE`, `OUTCOME_UNKNOWN` |
| `COMPLETED_SUCCESS` | Executor completed successfully; result hash recorded. | `TERMINATED` (terminal) |
| `COMPLETED_FAILURE` | Executor raised an error; redacted error label recorded. | `TERMINATED` (terminal) |
| `OUTCOME_UNKNOWN` | Process terminated during execution; recovered as `unknown` upon restart. | `TERMINATED` (terminal) |

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
