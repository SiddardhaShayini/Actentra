# Security Remediation Report: Finding F-4

**Target:** Success is recorded before postconditions are verified  
**Severity:** MEDIUM  
**Affected Source Files:**
- `sdk/python/actentra/boundary.py`
- `core/actentra_core/receipts.py`
- `sdk/python/actentra/__init__.py`
**Regression Test Suite:** `tests/unit/test_security_finding_04_postconditions.py`  
**Status:** **REMEDIATED & VERIFIED**

---

## 1. Executive Summary

In Actentra's execution model, `Boundary.execute()` allows callers to specify `verify_postcondition=True` along with a claim (such as `exists`, `absent`, or `digest_match`) to verify that an action produced its intended physical effect before granting execution or transition proof.

Prior to this remediation, `Boundary.execute()` committed an immutable `status="success"` outcome record into the SQLite receipt log **before** invoking the postcondition verifier. If verification subsequently refuted the claim (e.g., a file claimed to have been written was absent) or failed with an error, the immutable outcome receipt remained `status="success"`. Automated processes and auditors querying the receipt store observed contradictory records: an action marked as successful despite real-world verification refutation. Furthermore, `with contextlib.suppress(Exception):` silently swallowed any crash or exception in the verifier.

This remediation fixes the outcome sequencing: outcome persistence is strictly deferred until verification concludes, outcomes are mapped according to verification status, observation and outcome records are committed in a single atomic SQLite transaction, and `externally_verified` evidence is emitted only upon verified success.

---

## 2. Technical Vulnerability Analysis

### Root Cause: Premature Outcome Insertion
In `sdk/python/actentra/boundary.py:610-645` (prior to fix):
```python
# VULNERABLE CODE (Pre-remediation)
# 1. Action function executed
result = fn(envelope, decision)

# 2. Outcome recorded as "success" prematurely
self._store.record_outcome(
    crossing_id=envelope.crossing_id,
    session_id=envelope.session_id,
    canonical_hash=envelope.canonical_hash,
    policy_version=decision.policy_version,
    status="success",
    result_hash=result_hash,
    evidence_status="locally_observed",
)

# 3. Postcondition verifier invoked AFTER outcome is already sealed
if verify_postcondition and self._verifier is not None:
    with contextlib.suppress(Exception):
        obs = self._verifier.verify(
            resource=envelope.action.resource,
            claim=postcondition_claim,
            crossing_id=envelope.crossing_id,
        )
        self._store.record_observation(obs)
        if obs.status == "verified":
            # ... link evidence ...
```

Because `ReceiptStore._append_record()` enforces strict single-outcome immutability per crossing (`SELECT seq FROM receipts WHERE crossing_id = ? AND record_type = 'outcome'`), once an outcome was inserted as `status="success"`, it could never be updated or corrected. A subsequent observation with `obs.status == "refuted"` resulted in an irreconcilable conflict in the tamper-evident audit log:
- `receipts` record: `status="success"`
- `observations` record: `status="refuted"`

---

## 3. Remediation Architecture & Implementation

### 3.1. Deferred Outcome Finalization
In `sdk/python/actentra/boundary.py`:
- When `verify_postcondition=False`: Outcome is finalized immediately as `status="success"` and `evidence_status="locally_observed"`.
- When `verify_postcondition=True`: Outcome insertion is deferred until `self._verifier.verify()` completes.

### 3.2. Status Mapping Specification
| Verifier Status | Outcome Status | Evidence Status | Outcome Reason | External Evidence Emitted? | Budget Recorded? |
|---|---|---|---|---|---|
| `verified` | `success` | `externally_verified` | `None` | **Yes** (`EXTERNALLY_VERIFIED` + `verifies` causal link) | **Yes** |
| `refuted` | `failure` | `locally_observed` | `postcondition_refuted` | **No** | **No** |
| `error` | `unknown` | `unknown` | `postcondition_error` | **No** | **No** |
| `stale` | `unknown` | `stale` | `postcondition_stale` | **No** | **No** |
| Verifier exception | `unknown` | `unknown` | `postcondition_exception` | **No** | **No** |
| No verifier configured | `unknown` | `unknown` | `postcondition_unverified` | **No** | **No** |

### 3.3. Atomic Observation & Outcome Transaction in `ReceiptStore`
In `core/actentra_core/receipts.py`:
`ReceiptStore.record_outcome()` and `_append_record()` now accept an optional `observation: ObservationRecord | None = None` parameter. Inside the `BEGIN IMMEDIATE;` transaction:
1. If `observation` is provided, it is inserted/replaced into the `observations` table.
2. The immutable outcome receipt is inserted into the `receipts` table.
3. Both records are committed simultaneously. If any failure occurs, both are rolled back together.

### 3.4. Parametric Digest Verification
Added `postcondition_expected_digest: str | None = None` to `Boundary.execute()`, enabling callers to pass expected cryptographic hashes for `postcondition_claim="digest_match"`.

### 3.5. Fail-Closed Strict Exception Mode
Added `raise_on_postcondition_failure: bool = False` to `Boundary.execute()` and defined `PostconditionFailedError(ActentraError)`. Callers requiring contract-enforced failure can enable this flag to guarantee an exception is raised when postconditions are not verified.

---

## 4. Verification and Regression Testing

A dedicated test suite was implemented in `tests/unit/test_security_finding_04_postconditions.py` covering all requirements from `ADVERSARIAL_TEST_PLAN.md` (T-04):

| Test Case | Scenario Verified | Result |
|---|---|---|
| `test_postcondition_exists_verified_records_success` | File created; claim `exists` verified; outcome status `success`, evidence `externally_verified`. | **PASSED** |
| `test_postcondition_exists_refuted_records_failure_and_no_external_evidence` | File missing; claim `exists` refuted; outcome status `failure`, no external evidence emitted. | **PASSED** |
| `test_postcondition_absent_claim_semantics` | Verified when file deleted; refuted when file remains present. | **PASSED** |
| `test_postcondition_digest_match_claim_semantics` | Verified when sha256 matches; refuted when digest deviates. | **PASSED** |
| `test_postcondition_verifier_error_records_unknown` | Verifier error (e.g. missing digest param) recorded as `unknown` outcome. | **PASSED** |
| `test_postcondition_verifier_exception_records_unknown` | Verifier raising `OSError` caught cleanly and recorded as `unknown` outcome. | **PASSED** |
| `test_postcondition_stale_observation_records_unknown` | Stale observation timestamp maps to `unknown` outcome and `stale` evidence status. | **PASSED** |
| `test_postcondition_unconfigured_verifier_records_unknown` | `verify_postcondition=True` with `verifier=None` maps to `unknown` outcome. | **PASSED** |
| `test_raise_on_postcondition_failure_strictly_enforces_contract` | `raise_on_postcondition_failure=True` raises `PostconditionFailedError` on non-success. | **PASSED** |
| `test_atomic_observation_and_outcome_transaction` | Observation and outcome committed atomically in single SQLite transaction. | **PASSED** |

### Execution Proof:
```
tests\unit\test_security_finding_04_postconditions.py .......... [100%]
tests\unit\test_coordination.py .........                        [100%]
19 passed in 2.19s
uv run pytest -m "not slow" -q -> Passed (100%)
uv run ruff check core executors gateway sdk cli tests -> All checks passed!
uv run mypy -> Success: no issues found in 37 source files
```

---

## 5. Trust Model and Invariant Assessment

### Hardened Invariants
- **Invariant I2 (Fail Closed):** Actions whose postconditions cannot be verified are never recorded as successful executions.
- **Evidence Integrity:** Non-verified or refuted actions are strictly barred from generating `externally_verified` evidence records or causal verification links.
- **Audit Consistency:** Tamper-evident receipt logs guarantee that outcomes and observations are synchronized and transactionally consistent.

### Remaining Limitations
- **Verifier Confinement:** The built-in verifier (`WorkspaceFileVerifier`) is currently workspace-filesystem-confined. Non-filesystem mutation targets (e.g., remote HTTP webhooks, SQL tables, cloud SaaS APIs) require dedicated verifier implementations to confirm state transitions.
