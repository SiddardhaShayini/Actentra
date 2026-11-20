# Security Remediation Report: Finding F-3

**Target:** Warrant max-use counter is neither durable nor atomic at restart  
**Severity:** MEDIUM  
**Affected Source Files:**
- `core/actentra_core/receipts.py`
- `core/actentra_core/warrants.py`
- `sdk/python/actentra/boundary.py`
**Regression Test Suite:** `tests/unit/test_security_finding_03_warrant_quotas.py`  
**Status:** **REMEDIATED & VERIFIED**

---

## 1. Executive Summary

In Actentra's capability delegation architecture, a **Warrant** is a signed, scoped authorization token granting least-privilege authority to an agent or subagent without ambient credentials. Warrants may declare a finite `max_uses` constraint to bound delegation (e.g., granting a single action execution).

Prior to this remediation, `WarrantRegistry` tracked warrant consumption solely in a process-local in-memory dictionary bounded by an arbitrary limit of 1,000 entries. This design suffered from two critical security vulnerabilities:
1. **Zero Restart Durability:** Terminating and restarting a worker process, container, or `Boundary` instance wiped all memory state, resetting consumed warrant counters back to zero and allowing expired quotas to be replayed indefinitely until cryptographic expiry (`expires_at`).
2. **Cache Eviction Exploitability:** An attacker or compromised subagent could issue or invoke 1,001+ distinct dummy warrants to overflow the 1,000-entry in-memory dictionary. Because dictionary pruning evicted the oldest entries without verifying quota exhaustion status, an exhausted warrant's record was evicted, resetting its consumed count to zero.
3. **Concurrency Race Conditions:** The in-memory registry lacked transactional guarantees, permitting concurrent requests to race between counter inspection and increment, allowing quota overruns.

This remediation moves warrant consumption tracking from volatile memory into the persistent SQLite `ReceiptStore` backed by WAL mode and atomic `BEGIN IMMEDIATE` transactions.

---

## 2. Technical Vulnerability Analysis

### Root Cause 1: Volatile In-Memory Quota State
In `core/actentra_core/warrants.py:218-243`:
```python
# VULNERABLE CODE (Pre-remediation)
class WarrantRegistry:
    def __init__(self, max_warrants: int = 1000) -> None:
        self._max = max_warrants
        self._uses: dict[str, int] = {}
        self._limits: dict[str, int | None] = {}

    def record_use(self, warrant: Warrant) -> None:
        current = self._uses.get(warrant.warrant_id, 0)
        if warrant.max_uses is not None and current >= warrant.max_uses:
            raise WarrantError(f"Warrant {warrant.warrant_id} exceeded max uses ({warrant.max_uses})")
        if len(self._uses) >= self._max:
            oldest = next(iter(self._uses))
            self._uses.pop(oldest, None)
            self._limits.pop(oldest, None)
        self._uses[warrant.warrant_id] = current + 1
```

If the process restarted, `self._uses` was re-initialized to `{}`. Consequently, `self._uses.get(warrant.warrant_id, 0)` returned `0`, resetting quota consumption.

### Root Cause 2: Arbitrary Cache Eviction
When `len(self._uses) >= 1000`, the registry evicted `oldest = next(iter(self._uses))` regardless of whether the warrant had `consumed_uses >= max_uses`. Once evicted, any subsequent presentation of that warrant treated `current` as `0`.

### Root Cause 3: Unwired Boundary Registry
In `sdk/python/actentra/boundary.py:180-218`:
```python
# VULNERABLE CODE (Pre-remediation)
self._warrant_registry = warrant_registry  # Could be None
```
When callers instantiated `Boundary(policy, receipt_store)` without explicitly passing a `warrant_registry`, `self._warrant_registry` was `None`. In `_check_warrant()`, quota checks were simply skipped when `self._warrant_registry is None`, permitting unlimited uses.

---

## 3. Remediation Architecture & Implementation

### 3.1. Durable SQLite Schema (`ReceiptStore`)
In `core/actentra_core/receipts.py`, added a dedicated `warrant_usages` table initialized on DB startup:
```sql
CREATE TABLE IF NOT EXISTS warrant_usages (
    warrant_id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    holder TEXT NOT NULL,
    max_uses INTEGER,
    consumed_uses INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_warrant_usages_holder ON warrant_usages(holder);
CREATE INDEX IF NOT EXISTS idx_warrant_usages_expires ON warrant_usages(expires_at);
```

### 3.2. Atomic Concurrency with `BEGIN IMMEDIATE`
In `ReceiptStore.record_warrant_use()`, consumption is recorded inside a write transaction:
```python
def record_warrant_use(self, warrant: Warrant) -> int:
    # ...
    conn.execute("BEGIN IMMEDIATE;")
    row = conn.execute(
        "SELECT max_uses, consumed_uses FROM warrant_usages WHERE warrant_id = ?",
        (warrant.warrant_id,),
    ).fetchone()
    # If not registered at issuance, initialize dynamically
    # ...
    if max_uses is not None and consumed >= max_uses:
        raise WarrantError(
            f"Warrant {warrant.warrant_id} exceeded max uses ({max_uses}); consumed: {consumed}"
        )
    new_consumed = consumed + 1
    conn.execute(
        "UPDATE warrant_usages SET consumed_uses = ?, updated_at = ? WHERE warrant_id = ?",
        (new_consumed, now_iso, warrant.warrant_id),
    )
    conn.commit()
    return new_consumed
```
`BEGIN IMMEDIATE` acquires an exclusive reserved lock immediately before reading, eliminating TOCTOU race conditions between checking quota limits and incrementing usage.

### 3.3. Thread-Safe `WarrantRegistry` Integration
In `core/actentra_core/warrants.py`:
- `WarrantRegistry` accepts an optional `receipt_store: ReceiptStore | None` and `threading.Lock()`.
- Added `set_receipt_store(store)` method.
- `record_use()` and `remaining_uses()` delegate directly to `ReceiptStore` when available.
- Standalone in-memory fallback was hardened: when `len(self._uses) >= max_warrants`, the registry actively skips evicting entries whose quotas are exhausted (`current >= limit`), preventing eviction attacks even without a database.

### 3.4. Automatic Binding in `Boundary`
In `sdk/python/actentra/boundary.py`:
- If `warrant_registry` is provided, `Boundary.__init__` links `warrant_registry.set_receipt_store(self._store)`.
- If `warrant_registry` is `None`, `Boundary.__init__` automatically instantiates `WarrantRegistry(receipt_store=self._store)`.
- Capability warrants evaluated by `Boundary` are now always guaranteed durable, persistent quota enforcement by default.

---

## 4. Verification and Regression Testing

A dedicated test suite was implemented in `tests/unit/test_security_finding_03_warrant_quotas.py` covering all requirements from `ADVERSARIAL_TEST_PLAN.md` (T-03):

| Test Case | Scenario Verified | Result |
|---|---|---|
| `test_warrant_quota_survives_process_restart` | Warrant with `max_uses=1` used once; `Boundary` & `ReceiptStore` re-instantiated from disk; second use blocked with `warrant:exhausted`. | **PASSED** |
| `test_warrant_quota_resists_cache_eviction_attack` | Exhausted warrant subjected to 1,050 dummy warrant insertions; remaining uses remains 0; execution blocked. | **PASSED** |
| `test_concurrent_warrant_consumption_strictly_enforces_quota` | 20 concurrent worker threads compete for a warrant with `max_uses=3`; exactly 3 succeed, 17 blocked with `warrant:exhausted`. | **PASSED** |
| `test_standalone_warrant_registry_durability` | Multi-instance `WarrantRegistry` state persistence across discrete instances sharing SQLite DB. | **PASSED** |
| `test_warrant_issuance_registration` | Transactional warrant issuance logging with metadata retention. | **PASSED** |
| `test_unlimited_warrant_consumption_and_tracking` | `max_uses=None` warrants permit unlimited uses while maintaining cumulative audit count. | **PASSED** |
| `test_in_memory_registry_protects_exhausted_quotas_from_eviction` | In-memory fallback protects exhausted quotas from LRU eviction under memory pressure. | **PASSED** |

### Execution Proof:
```
tests\unit\test_security_finding_03_warrant_quotas.py ....... [100%]
tests\unit\test_warrants.py ......                            [100%]
============================== 13 passed in 11.74s ==============================
```

Full test suite verification:
```
uv run pytest -m "not slow" -q -> 100% passed (all tests green)
uv run ruff check core executors gateway sdk cli tests -> All checks passed!
uv run mypy -> Success: no issues found in 37 source files
```

---

## 5. Trust Model and Remaining Limitations

### Hardened Invariants
- **Quota Durability:** Capability tokens bounded by `max_uses` cannot be reset by terminating or restarting agent processes or gateways.
- **Eviction Immunity:** Cache flood attacks cannot restore authority to an exhausted warrant.
- **Strict Atomic Serializability:** High-concurrency races cannot cause quota overruns.

### Remaining Limitations
- **Multi-Node SQLite Concurrency:** SQLite WAL mode provides single-host multi-process concurrency. Distributed multi-region or Kubernetes multi-pod deployments require a distributed transactional store (e.g., PostgreSQL or Spanner) with distributed leasing or consensus.
- **Clock Skew:** Warrants rely on ISO-8601 UTC timestamps for `expires_at`. Host clock drift could prematurely expire or extend warrant validity. Enterprise production deployments should enforce NTP sync or trusted time attestations.
