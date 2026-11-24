# Actentra Production Reliability & Deployment Guide

This document provides operational and deployment guidance for running Actentra in high-reliability, security-critical environments.

---

## 1. System Architecture & Reliability Invariants

Actentra enforces **Invariant I16 (Transactional Execution Lifecycle & Durable Idempotency)** alongside its core fail-closed authorization kernel.

### Execution Lifecycle State Machine

Every action crossing transitions through an explicit, auditable, and crash-resilient state machine stored in SQLite under `BEGIN IMMEDIATE` transactions.

```
       [Created]
           |
           v
      [Authorized]
      /          \
     v            v
 [Approved]    [Claimed]
     \            /
      v          v
       [Executing]
       /    |    \
      v     |     v
 [Succeeded]| [Verification Pending]
            |     /      |       \
            v    v       v        v
         [Failed]   [Unknown]   [Reconciliation Required]
                        \        /
                         v      v
                      [Reconciled]
```

#### Transition Matrix

| From State | Legal To States | Trigger / Description |
|---|---|---|
| `created` | `authorized`, `failed` | Policy evaluation or envelope validation failure |
| `authorized` | `approved`, `claimed`, `failed` | Human approval, direct claim, or policy denial |
| `approved` | `claimed`, `failed` | One-time execution claim or expiration/revocation |
| `claimed` | `executing`, `failed` | Dispatch to executor or claim expiration |
| `executing` | `verification_pending`, `succeeded`, `failed`, `unknown`, `reconciliation_required` | Tool returns, verification initiated, error, timeout, or crash |
| `verification_pending` | `succeeded`, `failed`, `unknown`, `reconciliation_required` | Independent verifier confirms, refutes, or crashes |
| `unknown` | `reconciliation_required`, `succeeded`, `failed` | Interrupted outcome flagged for manual or verifier reconciliation |
| `reconciliation_required` | `succeeded`, `failed`, `unknown` | Operator or external evidence confirms outcome |
| `succeeded` | *(terminal)* | Final verified success; immutable |
| `failed` | *(terminal)* | Final failure; immutable |

Any attempt to execute an invalid transition raises `InvalidStateTransitionError` and rolls back atomically.

---

## 2. Durable Idempotency & Replay Protection

To prevent side-effect duplication during network retries or caller crashes, Actentra supports durable idempotency keys:

- **Key Binding**: Idempotency keys are bound to `(principal_id, idempotency_key)`.
- **Payload Verification**: If a key is submitted with differing parameters, canonicalization detects the hash discrepancy and immediately raises `IdempotencyConflictError`.
- **At-Most-Once Execution**:
  - **In-Flight Protection**: If an execution is in progress, concurrent requests with the same key are blocked with `IdempotencyInFlightError`.
  - **Cached Result Replay**: When an execution has completed, replaying the request returns the cached result without re-executing the tool or creating duplicate outcome receipts.
  - **Uncertain Protection**: If an action crashed mid-flight, replay is blocked with `ReconciliationRequiredError` until explicit reconciliation occurs.

---

## 3. Crash Recovery & Startup Reconciliation

Upon startup, `ReceiptStore.recover_system_state()` automatically audits and reconciles all persistent subsystems:

1. **Pending Approvals**: Cleans up expired approvals (`status = 'expired'`).
2. **Resource Leases**: Cleans up expired multi-agent leases (`status = 'expired'`).
3. **Execution Claims**: Expires dangling unconsumed claims.
4. **Action Lifecycles**: Actions left in `executing` or `verification_pending` during a crash are transitioned to `reconciliation_required`, with an audit transition entry recorded.
5. **Idempotency Records**: Records left in `in_flight` are transitioned to `reconciliation_required`.
6. **Pending Outcomes**: Interrupted decisions lacking an outcome receipt are durably finalized as `status = "unknown"`.
7. **Temporary Files**: Residual temporary checkpoint files (`.tmp_*`) are safely removed.

Both `Boundary.__init__` and `AppServices.__init__` invoke `recover_system_state()` automatically on startup.

---

## 4. Database Configuration & Resilience

### SQLite Engine Settings

Actentra receipt databases must be configured with:

- **Journal Mode**: `WAL` (Write-Ahead Logging) enables concurrent readers without blocking writers.
- **Synchronous**: `NORMAL` (default) or `FULL`.
- **Foreign Keys**: `ON` enforces relational integrity constraints.
- **Busy Timeout**: `PRAGMA busy_timeout = 15000;` ensures threads wait up to 15 seconds during write contention rather than immediately failing with `SQLITE_BUSY`.
- **Transactions**: State mutations execute under `BEGIN IMMEDIATE` to prevent concurrent write deadlocks.

### Database Integrity Verification

Call `ReceiptStore.validate_database_integrity()` to verify:
1. SQLite low-level B-tree structure (`PRAGMA quick_check;`).
2. Sequence continuity (receipts `seq` from $1$ to $N$ with no gaps).
3. Hash chain continuity (each record's `prev_hash` links to the previous `entry_hash`).

If persistent storage is inaccessible or corrupted, Actentra **fails closed** and raises `DatabaseUnavailableError`. It never silently defaults to an empty in-memory state.

---

## 5. Health Checks & Observability

### Health Endpoint (`GET /health`)

Returns real-time status and database integrity:

```json
{
  "status": "ok",
  "db_status": "healthy",
  "db_integrity_ok": true,
  "policy_id": "production-policy",
  "policy_version": "v1:sha256:...",
  "mode": "enforce",
  "frozen": false,
  "total_receipts": 1420,
  "integrity_ok": true,
  "last_hash": "sha256:...",
  "pending_approvals_count": 0,
  "registered_executors": ["fs.read", "fs.write", "sql.execute"]
}
```

### Metrics Endpoint (`GET /v1/metrics`)

Returns operational counters and latency histograms without leaking secrets:

```json
{
  "uptime_seconds": 3600.0,
  "crossings": {
    "total": 520,
    "allowed": 510,
    "denied": 8,
    "asked": 2,
    "held": 0
  },
  "executions": {
    "dispatched": 510,
    "succeeded": 508,
    "failed": 2,
    "unknown": 0
  },
  "idempotency": {
    "registered": 120,
    "cached_hits": 45,
    "conflicts": 0,
    "in_flight_blocks": 0,
    "reconciliation_required": 0
  },
  "storage": {
    "database_healthy": true,
    "database_path": "/var/lib/actentra/receipts.db",
    "db_retries": 0,
    "db_errors": 0,
    "integrity_checks_passed": 12,
    "recoveries_completed": 1
  },
  "latencies": {
    "tool:fs.read": {
      "count": 450,
      "avg_ms": 1.25,
      "p50_ms": 1.10,
      "p95_ms": 2.40,
      "p99_ms": 4.10,
      "max_ms": 8.50
    }
  }
}
```

---

## 6. Operational Runbook & Disaster Recovery

### Handling Uncertain Outcomes (`status = "unknown"`)

1. Query pending unknown outcomes:
   ```bash
   python -m actentra.cli receipts list --status unknown
   ```
2. Inspect the resource state and relevant evidence logs.
3. Once the actual state is determined, reconcile the outcome:
   ```python
   services.reconcile_outcome(crossing_id, observation=verified_obs)
   ```
   Reconciliation updates `action_lifecycle` to `succeeded` or `failed` and records an immutable entry in `outcome_reconciliations`.

### Database Backup & Restore

1. **Online Backup**: Use the SQLite online backup API or `sqlite3 receipts.db ".backup backup.db"` to safely capture the WAL state.
2. **Integrity Check**: Always verify the backup before archiving:
   ```python
   store = ReceiptStore("backup.db")
   ok, msg = store.validate_database_integrity()
   assert ok, f"Corrupted backup: {msg}"
   ```
3. **External Checkpoints**: Ensure signed checkpoints are published to an independent anchor (e.g., S3 or immutable file anchor) using `create_external_checkpoint()`.
