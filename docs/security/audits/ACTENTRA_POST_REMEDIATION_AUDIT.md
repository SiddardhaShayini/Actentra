# ACTENTRA Post-Remediation Audit

**Assessment date:** 2026-11-25  
**Repository:** SiddardhaShayini/Actentra  
**Audited HEAD:** `85b663a` (`fix(core,gateway): enforce deployment security profiles and external audit anchoring (Phase 5)`)  
**Platform:** Windows 11/amd64, Python 3.12 (`pyproject.toml`: Python >=3.12)  
**Scope:** Source review, local reproduction, unit/integration/end-to-end-style tests, property tests, race tests, mTLS tests, crash/corruption tests, and package smoke tests.

## 1. Executive summary

Actentra at HEAD `85b663a` has materially improved its security boundary compared with the earlier implementation. Independent execution of the configured-bearer path rejected `operator:attacker`, and the standalone warrant registry now fails closed at capacity instead of evicting exhausted quotas. The complete pytest suite passed 403 tests with one platform-privilege skip.

The implementation now provides credible local enforcement for:

- strict bearer-token and mTLS principal binding;
- grant-attested delegation;
- durable warrant consumption;
- policy-gated, claim-bound execution;
- postcondition-checked success promotion;
- resource-bound observations;
- replay-resistant claims and outcomes;
- Windows handle-relative filesystem confinement;
- receipt database integrity checks and crash/recovery transitions.

These controls do not establish process isolation, independent remote execution attestation, or a Linux/POSIX race guarantee. Production success is therefore not the recommended verdict.

**Final verdict: Suitable for restricted controlled pilots.** The verdict applies only to trusted same-host code, disposable or explicitly authorized targets, and deployments that satisfy the restrictions in Section 9.

## 2. Method and evidence

No production source or test source was modified for this audit. The worktree remained clean. Validation included:

- full pytest suite;
- focused security suites;
- real loopback TLS/mTLS socket tests;
- Windows real-filesystem race tests;
- Hypothesis property tests;
- SQLite corruption and crash-recovery tests;
- Ruff and strict mypy;
- source-distribution and wheel build;
- isolated wheel install and import smoke test.

Representative commands:

```text
uv run pytest -o addopts= -q
403 passed, 1 skipped in 36.25s

uv run pytest -o addopts= -q -rs
403 passed, 1 skipped
skip: tests/unit/test_fs_executor.py:207
reason: OS privilege prevents creating symlinks in this test environment

uv run pytest -o addopts= -q -rs
  tests/unit/test_phase3_fs_race_confinement.py
  tests/unit/test_phase4_mtls_principal_binding.py
  tests/unit/test_phase7_production_reliability.py
  tests/chaos/test_chaos.py
  tests/property/test_properties.py
33 passed

uv run ruff check core executors gateway sdk cli tests
All checks passed

uv run mypy
Success: no issues found in 41 source files

uv build
Successfully built dist/actentra-0.1.0a0.tar.gz
Successfully built dist/actentra-0.1.0a0-py3-none-any.whl
```

An isolated virtual environment was created outside the repository. The wheel was reinstalled with runtime dependencies and all major package namespaces imported successfully.

## 3. Original eight findings

| # | Original finding | Status | Evidence |
|---|---|---|---|
| 1 | Delegation grant binding | **VERIFIED REMEDIATED** | Configured mapped principals and registry grants are validated; caller-supplied delegation is rejected unless bound to an active grant. Independent reproduction with `operator:attacker` and a configured secret returned `IdentitySecurityError`. |
| 2 | Remote plaintext transport | **VERIFIED REMEDIATED** | Remote deployment construction requires TLS and rejects missing server certificates or absent mTLS configuration as applicable. Real HTTPS/mTLS loopback tests passed. |
| 3 | Missing GET scope authorization | **VERIFIED REMEDIATED** | Read routes call scope/object authorization before returning approvals, crossings, lifecycle transitions, and receipts; focused authorization suites passed. |
| 4 | Caller-controlled session isolation | **VERIFIED REMEDIATED** | Session creation and reuse enforce caller ownership; supplied session IDs are denied or isolated from unrelated principals. Restart and concurrent isolation tests passed. |
| 5 | SQLite table authorization | **VERIFIED REMEDIATED** | Direct SQL/executor interfaces reject disallowed attachment and blocked-table operations. Full suite and executor hardening tests passed. |
| 6 | Postcondition binding | **VERIFIED REMEDIATED** | Verification context binds crossing, action hash, resource, claim, executor, verifier, policy, expected claim/digest, observation time, and expiry. Success is promoted only after verified matching state. |
| 7 | Receipt-chain tampering | **VERIFIED REMEDIATED** | Hash-chained receipts, checkpoint verification, sequence-gap detection, and corruption fail-close behavior passed. No independent external anchoring key is assumed. |
| 8 | Filesystem symlink race | **PARTIALLY REMEDIATED / PLATFORM-LIMITED** | Windows handle-relative confinement and descriptor-relative POSIX confinement are implemented. Real Windows race tests passed; symlink creation was skipped because the test environment lacks the required privilege. No Linux/macOS or unrestricted POSIX real-symlink run was performed. |

## 4. Independent reproductions

### 4.1 Configured structured bearer-token bypass

Command-level reproduction:

```text
resolve_http_caller_context(
    Authorization: Bearer operator:attacker,
    expected_token: configured-secret,
    remote_addr: 203.0.113.10,
    enforce_strict_shared_token: True
)

IdentitySecurityError:
Invalid or unauthorized bearer token: does not match configured authentication secret
```

Relevant source:

- bearer parsing and configured-token fail-close: [identity.py](/D:/Actentra/core/actentra_core/identity.py:1420)
- structured-token rejection: [identity.py](/D:/Actentra/core/actentra_core/identity.py:1748)
- HTTP auth entry point: [http_service.py](/D:/Actentra/gateway/actentra_gateway/http_service.py:665)

Status: no reproduction of the original structured bearer bypass at this HEAD.

### 4.2 Standalone finite-use warrant replay

An independent in-memory reproduction created a finite-use warrant, consumed it once, then attempted additional finite-use and replay operations. The implementation returned `WarrantError` for registry saturation and again rejected the exhausted warrant.

Relevant source:

- memory fail-close capacity logic: [warrants.py](/D:/Actentra/core/actentra_core/warrants.py:268)
- no-eviction rule: [warrants.py](/D:/Actentra/core/actentra_core/warrants.py:294)
- SQLite durable use: [warrants.py](/D:/Actentra/core/actentra_core/warrants.py:274)

Status: the original quota-reset replay is not reproducible in the standalone in-memory fallback.

### 4.3 Gateway `execute=True` postcondition bypass

The gateway registers the authoritative dispatcher and does not record success before local or independent verification. Executions with lying or wrong-content executors produced failure/unknown outcomes rather than success.

Relevant source:

- gateway authoritative dispatch: [services.py](/D:/Actentra/gateway/actentra_gateway/services.py:694)
- postcondition extraction and validation: [services.py](/D:/Actentra/gateway/actentra_gateway/services.py:742)
- success promotion after verification: [services.py](/D:/Actentra/gateway/actentra_gateway/services.py:1085)
- HTTP `execute=True` handling: [http_service.py](/D:/Actentra/gateway/actentra_gateway/http_service.py:1246)

Status: reproduction attempts passed; no gateway execute-bypass was found.

### 4.4 Unrelated observation promotion

Crossing-bound verification requires the observed resource to equal the authorized resource and consumes matching observations once.

Relevant source:

- resource mismatch rejection: [services.py](/D:/Actentra/gateway/actentra_gateway/services.py:1713)
- observation binding and consumption: [services.py](/D:/Actentra/gateway/actentra_gateway/services.py:1764)

Status: no unrelated-resource promotion reproduction passed.

### 4.5 Filesystem write race around `os.replace()`

The implementation uses temporary files under held ancestor handles and descriptor-relative replacement.

Relevant source:

- Windows parent verification and replacement: [fs.py](/D:/Actentra/executors/actentra_executors/fs.py:638)
- POSIX `dir_fd` replacement: [fs.py](/D:/Actentra/executors/actentra_executors/fs.py:663)

Real concurrency tests passed on Windows. The audit found no reproduction of an escape through the replacement step on the exercised platform.

### 4.6 mTLS/application principal mismatch

Real loopback TLS/mTLS tested Alice certificate plus Bob bearer token and required matching principal identity. The mismatch returned 403. Matching Alice certificate plus Alice token returned 200.

Relevant source:

- transport/application binding: [identity.py](/D:/Actentra/core/actentra_core/identity.py:1458)
- real socket test: [test_phase4_mtls_principal_binding.py](/D:/Actentra/tests/unit/test_phase4_mtls_principal_binding.py:406)

Status: no mTLS/application mismatch bypass reproduced.

### 4.7 Mock-only filesystem race weakness

Mock-based tests remain useful but do not replace OS-level races. The repository does contain real filesystem race tests, so this is no longer purely mock coverage. However, symlink/junction creation is skipped on this host, and Linux/macOS junction behavior was not exercised.

Status: **remaining test/evidence gap, not a demonstrated escape on the audited Windows platform**.

## 5. New findings

| # | Finding | Status | Assessment |
|---|---|---|---|
| 1 | Gateway `execute=True` postcondition bypass | **REMEDIATED** | `execute=True` routes through the same verification-aware dispatcher. |
| 2 | Unrelated observation promotion | **REMEDIATED** | Resource, claim, crossing, and digest binding are checked. |
| 3 | Filesystem write race around `os.replace()` | **NO REPRODUCTION / PLATFORM-LIMITED** | Handle/descriptor-relative confinement is implemented and Windows race tests pass; broader POSIX validation remains. |
| 4 | mTLS/application principal mismatch | **REMEDIATED** | Real socket mismatch tests failed closed; mismatch rejects 403. |
| 5 | Mock-only filesystem race test weakness | **REMAINING TEST GAP** | Real race tests exist, but privileged symlink creation and other POSIX platforms were not exercised here. |

## 6. Attack-surface search

The audit searched for direct executor calls, alternate success paths, unprotected service methods, missing route authorization, principal substitution, observation reuse, claim replay, digest substitution, path normalization, races, checkpoint downgrade, key substitution, fail-open behavior, and unknown-to-success promotion.

Results:

- direct SDK and gateway execution paths converge on policy/claim/postcondition mechanisms;
- replayed observations and claims are rejected by consumed-state and crossing bindings;
- digest substitution is rejected against the authorized context;
- action lifecycle transitions reject unknown-to-succeeded promotion;
- database and policy corruption tests fail closed;
- real mTLS mismatch and certificate substitution tests failed closed;
- checkpoint downgrade/key-substitution paths were covered by focused trust-anchoring tests;
- the remaining filesystem risk is OS-level TOCTOU coverage, not a reproduced source defect.

## 7. Security invariant verification

| Invariant | Result |
|---|---|
| Authenticated identity is required before execution | PASS on configured and mTLS-backed routes |
| Delegation must be registered and bound | PASS for active/signed/registry-bound grants |
| Caller cannot choose or isolate arbitrary sessions | PASS for enforced session ownership |
| Policy deny/hold cannot execute | PASS in focused and full suites |
| Approval scope and object authorization are enforced | PASS |
| Execution claim is crossing/principal bound and single-use | PASS |
| Executor return alone cannot prove success | PASS |
| External observation must match resource/digest/context | PASS |
| Unknown/refuted/error results cannot become success | PASS |
| Warrant quota does not reset in memory or SQLite fallback | PASS |
| Receipt chain detects tampering/sequence gaps | PASS |
| Corruption and policy reload failures fail closed | PASS |
| Real filesystem and network guarantees are platform-bounded | DOCUMENTED LIMIT |

## 8. Test execution results

| Category | Result |
|---|---|
| Full unit tests | Included in 403-test full suite |
| Integration tests | Included in full suite |
| End-to-end-style gateway/HTTP tests | Included in full suite |
| Adversarial security tests | Included in full suite |
| Property-based Hypothesis tests | 33-test focused subset passed |
| Fuzz tests | No dedicated fuzzer framework or fuzz corpus; property tests were used where applicable |
| Concurrency tests | Passed, including idempotency, claims, warrants, outcomes, and lifecycle |
| Real filesystem race tests | Windows real race tests passed |
| TLS/mTLS integration | Real loopback TLS/mTLS tests passed |
| Crash/recovery tests | Passed |
| Database corruption tests | Passed |
| Ruff/mypy | Passed |
| Source/wheel build | Passed |
| Isolated wheel install/import | Passed with runtime dependencies |

## 9. Remaining risks and deployment restrictions

1. **Actentra is not an OS sandbox.** Arbitrary in-process code can bypass Actentra APIs.
2. **External success remains caller-/local-verifier-dependent.** A receipt proves an observed or caller-reported lifecycle, not independent remote state unless an approved external witness model is used.
3. **Filesystem guarantees are platform-specific.** Linux/macOS and unrestricted POSIX symlink/junction behavior are not certified by this Windows run.
4. **SQLite is local trust anchoring, not distributed consensus.** Host administrators, backup replacement, and database key access require separate controls.
5. **Crash windows remain.** A side effect can precede an outcome or reconciliation record; reconciliation is required to determine indeterminate state.
6. **No external penetration test or third-party dependency audit was performed.**
7. **No release-signing or independent external checkpoint service was validated.**
8. **No real public-network SSRF test was performed.** DNS/socket pinning has focused and unit coverage, but external DNS and network behavior were not tested.
9. **Shared bearer mode is less strong than mTLS or mapped principal tokens.** Remote deployment should require mTLS or cryptographic principal mappings.

## 10. Production-readiness assessment

Actentra is suitable for controlled pilot use, not unconditional external production deployment.

Approved pilot conditions:

- run in remote mode only with TLS and mTLS/principal mappings;
- prohibit caller-asserted identity/delegation fields unless backed by a signed, registry-validated grant;
- use SQLite-backed warrant/quota enforcement;
- require strict postconditions for mutating operations;
- use independently authorized resource verifiers;
- restrict filesystem workspace roots and host privileged users;
- retain the same-host threat model and local audit-trust assumptions;
- reconcile unknown or crash-indeterminate outcomes rather than converting them to success;
- monitor external checkpoint and receipt-chain integrity;
- rerun a POSIX symlink race campaign on each supported POSIX deployment platform.
