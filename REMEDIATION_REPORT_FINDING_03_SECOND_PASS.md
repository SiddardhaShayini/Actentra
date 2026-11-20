# Remediation Report: Finding 03 (Second-Pass) — Warrant Quota Durability, Atomicity, and Non-Evictable Quota Enforcement

**Audit Commit:** `02887cd`  
**First Remediation Commit:** `910f463`  
**Independent Validation Commit:** `35c9ed7`  
**Finding ID:** F-3 / R-2 (Enterprise Security Audit)  
**Severity:** MEDIUM  
**Status:** VERIFIED REMEDIATED  
**Date:** 2026-11-20  

---

## 1. Executive Summary

During the initial remediation of Finding 03 (`910f463`), durable warrant quota tracking in SQLite (`ReceiptStore.warrant_usages`) was introduced using `BEGIN IMMEDIATE` transactions. In addition, the SDK `Boundary` class was updated to automatically wire its `ReceiptStore` into `WarrantRegistry`.

However, an independent security validation (`35c9ed7`) identified a critical residual vulnerability in the standalone in-memory fallback path (`core/actentra_core/warrants.py:260-290`):
- When `WarrantRegistry` was used standalone (without a `ReceiptStore`), it retained an emergency eviction cap at `len(self._uses) >= self._max_warrants * 2` that forcibly evicted the oldest entries via `self._uses.pop(oldest)` regardless of whether the warrant had a finite quota (`max_uses is not None`) or was exhausted.
- **Exploit Reproduction:** An attacker or subagent presenting a consumed `max_uses=1` warrant could flood the standalone registry with other finite-use warrants, causing the target warrant to be evicted. Once evicted, its consumed count was wiped, resetting `remaining_uses` back to `1` and allowing an exhausted finite-use warrant to be replayed.

This second-pass remediation enforces an explicit security contract:
1. **Zero Quota-Resetting Eviction:** Under no circumstances are active or exhausted finite-use warrants (`max_uses is not None`) evicted from in-memory tracking. Eviction that would reset a quota is strictly forbidden.
2. **Safe Eviction Order:** When memory capacity is reached, the registry prunes only provably expired warrants (`expires_at <= now`) or unlimited warrants (`max_uses is None`).
3. **Fail-Closed on Saturation:** If an in-memory registry reaches capacity and contains exclusively non-expired finite-use warrants, any attempt to record additional warrants fails closed with `WarrantError` instead of evicting consumed quotas.
4. **Explicit Durability Contract:** `WarrantRegistry` exposes `is_durable` and `require_durable`. When `require_durable=True`, finite-use warrants are rejected immediately in standalone in-memory mode, preventing accidental volatile quota enforcement.

---

## 2. Vulnerability Reproduction & Root Cause Analysis

### 2.1 Attack Vector: In-Memory Eviction Replay

#### Reproduction Path:
1. Initialize an in-memory registry with a small capacity:
   ```python
   reg = WarrantRegistry(max_warrants=2)
   ```
2. Issue and consume a finite-use warrant:
   ```python
   target = issue_warrant(holder="target", max_uses=1, ...)
   reg.record_use(target)
   assert reg.remaining_uses(target) == 0  # Exhausted
   ```
3. Issue and consume 4 distinct finite-use warrants to exceed $2 \times \text{max\_warrants}$:
   ```python
   for i in range(4):
       w = issue_warrant(holder=f"agent-{i}", max_uses=1, ...)
       reg.record_use(w)
   ```
4. Prior to this remediation, lines 286-290 in `core/actentra_core/warrants.py` executed:
   ```python
   elif len(self._uses) >= self._max_warrants * 2:
       oldest = next(iter(self._uses))
       del self._uses[oldest]
       self._limits.pop(oldest, None)
   ```
   This deleted `target.warrant_id` from `self._uses`.
5. Upon the next call:
   ```python
   reg.remaining_uses(target)  # Returned 1! (Reset to max_uses)
   reg.record_use(target)      # Succeeded! (Quota replay exploit)
   ```

### 2.2 Root Cause

The emergency fallback logic conflated volatile cache management with security quota enforcement. While unlimited warrants or disk-backed cache entries can be evicted without compromising security, evicting the sole record of a finite-use warrant's consumption destroys the security boundary.

---

## 3. Remediation Implementation

### 3.1 Strict In-Memory Eviction Rules (`core/actentra_core/warrants.py`)

- **Non-Evictable Finite Quotas:**
  Active and exhausted finite-use warrants (`max_uses is not None`) that have not passed their cryptographic expiration date (`expires_at`) are never evicted.
- **Ordered Safe Pruning:**
  When `len(self._uses) >= self._max_warrants` and an incoming warrant is not already tracked in memory:
  1. **Expired Warrants:** The registry scans `self._expires` for warrants where `now >= expires_at`. These are pruned safely because `verify_warrant()` rejects expired tokens regardless of quota state.
  2. **Unlimited Warrants:** The registry scans `self._limits` for entries where `max_uses is None`. Pruning unlimited warrants is safe because they do not have a finite quota to enforce.
  3. **Fail Closed:** If all entries in memory are active/exhausted non-expired finite-use warrants, the registry refuses to evict any entry and raises `WarrantError`:
     ```python
     raise WarrantError(
         f"In-memory warrant registry capacity ({self._max_warrants}) saturated "
         "with finite-use warrants. Cannot evict active or exhausted quotas "
         "without durable storage. Attach a ReceiptStore or increase max_warrants."
     )
     ```

### 3.2 Explicit Durability Contract

- **`require_durable: bool = False` Parameter:**
  Allows callers to mandate durable persistence. When `True`, attempting to record a finite-use warrant without an attached `ReceiptStore` immediately raises `WarrantError`.
- **`is_durable: bool` Property:**
  Returns `True` if backed by a persistent `ReceiptStore` / SQLite database, `False` for ephemeral in-memory operation.
- **`is_exhausted(warrant: Warrant) -> bool` Helper:**
  Provides an explicit, thread-safe boolean query for warrant quota exhaustion.
- **`clear() -> None` Method:**
  Explicitly clears in-memory state when resetting test harnesses.

### 3.3 Authoritative SQLite Write-Through Integration

When `receipt_store` is configured (the default SDK `Boundary` operation mode):
- Every call to `record_use(warrant)` executes an atomic `BEGIN IMMEDIATE` transaction in SQLite against the `warrant_usages` table.
- In-memory pruning of `self._uses` is purely an LRU cache size bound that has no impact on security, because `ReceiptStore.get_warrant_remaining_uses()` queries SQLite directly.

---

## 4. Adversarial Regression Test Suite

The test suite in `tests/unit/test_security_finding_03_warrant_quotas.py` was expanded with 5 dedicated adversarial test cases covering the full matrix of failure modes:

| Test Case | Scenario Tested | Outcome |
|---|---|---|
| `test_adversarial_in_memory_quota_replay_via_finite_warrant_flooding` | Floods in-memory registry with finite-use warrants beyond capacity | Target warrant is preserved; replay raises `WarrantError` |
| `test_adversarial_in_memory_capacity_saturation_fails_closed` | In-memory registry completely filled with active finite-use warrants | New warrant fails closed; existing 3 quotas undamaged |
| `test_adversarial_in_memory_partial_quota_preservation_under_pressure` | Warrant with `max_uses=5` consumed 2 times under cache pressure | Quota remains exactly 3; never reset to 5 |
| `test_adversarial_in_memory_require_durable_enforcement` | `require_durable=True` without a `ReceiptStore` | Finite warrants rejected; unlimited warrants allowed |
| `test_adversarial_expired_warrant_pruning_under_pressure` | Expired finite-use warrants present under cache pressure | Expired warrant pruned safely; active quotas preserved |

---

## 5. Verification Results

### 5.1 Test Suites

- **Finding 03 Test Suite (12 tests):**
  ```bash
  uv run pytest tests/unit/test_security_finding_03_warrant_quotas.py
  # 12 passed in 10.45s
  ```
- **Warrants Test Suite (6 tests):**
  ```bash
  uv run pytest tests/unit/test_warrants.py
  # 6 passed in 0.88s
  ```
- **All Security Finding Suites (96 tests):**
  ```bash
  uv run pytest tests/unit/test_security_finding_01_identity.py \
                 tests/unit/test_security_finding_02_dns_rebinding.py \
                 tests/unit/test_security_finding_03_warrant_quotas.py \
                 tests/unit/test_security_finding_04_postconditions.py \
                 tests/unit/test_security_finding_05_external_outcomes.py \
                 tests/unit/test_security_review_remediations.py
  # 96 passed in 23.36s
  ```
- **Full Fast Test Suite:**
  ```bash
  uv run pytest -m "not slow" -o addopts= -q
  # 244 passed, 4 skipped in 43.68s
  ```

### 5.2 Linting & Static Typing

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

1. **Process Restarts in Standalone Mode:**
   Process restarts terminate volatile memory. Applications requiring quota survival across container, worker, or process restarts must use the SQLite-backed `ReceiptStore` (which is standard and automatic in `Boundary`).
2. **In-Memory Capacity Bounds:**
   In purely in-memory mode, if an application presents thousands of concurrent active finite-use warrants exceeding `max_warrants`, subsequent operations fail closed. Applications with high warrant volume must configure `max_warrants` appropriately or attach a persistent `ReceiptStore`.
