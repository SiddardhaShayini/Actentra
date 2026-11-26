# Actentra — Integrated Adversarial Test Report

**Assessment date:** 2026-11-20  
**Test boundary:** Local repository code, deterministic unit tests, and method-level reproductions only  
**External systems contacted:** None

## Result overview

The dedicated remediation suites and complete fast suite pass, but two cross-cutting identity/quota protections failed independent local reproductions. Tests in the repository primarily validate each remediation in isolation; crash recovery, authenticated gateway integration for the token-prefix bypass, and multi-component attack chains were not performed.

## Scenarios and outcomes

| Scenario | Method | Outcome | Evidence / limitation |
|---|---|---|---|
| Authenticated agent forges a delegation to a victim | Called `resolve_http_caller_context()` using `Bearer agent:attacker` and `X-Actentra-Delegated-By: victim`. | **EXPLOIT REPRODUCED** | Returned `allowed_agents=['attacker', 'victim']`; `is_agent_allowed('victim') == True`. No parent-issued delegation is checked. |
| Remote caller bypasses configured shared bearer token using structured operator token | Called resolver with `expected_token='configured-secret'` and `Bearer operator:attacker`. | **EXPLOIT REPRODUCED** | Returned authenticated operator with wildcard scopes and trusted-operator status. The HTTP handler separately accepts the structured prefix. |
| Combine forged operator identity with administrative operations | Source-level trace of auth gate and operator context. | **BYPASS PATH CONFIRMED; endpoint attack not executed** | Operator contexts have wildcard scopes. No remote HTTP request was made; the method-level resolver reproduction established the principal. |
| Use a limited warrant, flood standalone registry, replay it | Called `WarrantRegistry(max_warrants=2)` with valid locally signed finite-use warrants. | **EXPLOIT REPRODUCED** | After the target was evicted, remaining uses reset to 1 and replay succeeded. SQLite-backed `Boundary` is not affected by this specific fallback path. |
| DNS answer changes between validation and connection / mixed public-private answers | Existing simulated resolver/socket regression tests. | **BLOCKED IN TESTS** | DNS suite passed within the 59 targeted tests. No real network endpoint was contacted. |
| Redirect to a private/metadata address or unsafe scheme | Existing redirect-handler unit regressions with controlled resolver results. | **BLOCKED IN TESTS** | Existing tests passed. No cloud metadata endpoint was contacted. |
| Concurrent consumption of one SQLite-backed limited warrant | Existing focused concurrency regression test. | **PASSING REGRESSION** | The suite asserts only the configured number of concurrent uses succeed; suite passed. No separate multi-process stress was run in this audit. |
| Executor returns successfully but postcondition is refuted/error/stale | Existing verifier regression cases. | **RECORDED AS FAILURE/UNKNOWN IN TESTS** | The suite passed. No external irreversible target was used. |
| Process crashes after side effect but before verification/outcome | No process-kill/fault injection run. | **NOT TESTED** | Current code does not demonstrate recovery of a dispatched-but-unfinalized action; absence of an outcome must not be treated as success. |
| Replay a claim or submit another executor’s claim | Existing outcome claim regression cases. | **REJECTED IN TESTS** | Outcome suite passed; claim consumption is one-time and principal-bound in the gateway path. |
| Concurrent conflicting outcome reports | No concurrent HTTP outcome race test run in this audit. | **NOT TESTED** | Storage claim consumption is transactional, but the complete consume-claim / outcome-record sequence uses separate transactions. |
| Directly call service methods without `caller_context` | Source review only. | **TRUSTED-IN-PROCESS PATH IDENTIFIED** | Several service methods skip principal checks when context is `None`; outcome compatibility can internally issue/consume a claim. This is not an HTTP bypass by itself, but services are not a security boundary for untrusted in-process plugins. |
| Windows junction/symlink swap during filesystem operation | Source review only. | **NOT TESTED; PLAUSIBLE RACE** | Path containment is checked before name-based read/write/delete calls. A Windows-specific race test is still needed. |

## Commands run and exact results

- `uv run pytest -o addopts= -q tests/unit/test_security_finding_01_identity.py tests/unit/test_security_finding_02_dns_rebinding.py tests/unit/test_security_finding_03_warrant_quotas.py tests/unit/test_security_finding_04_postconditions.py tests/unit/test_security_finding_05_external_outcomes.py`  
  **59 passed in 4.65s.**
- `uv run pytest -m "not slow" -o addopts= -q`  
  **228 passed, 1 skipped in 14.62s.**
- `uv run ruff check core executors gateway sdk cli tests`  
  **All checks passed.**
- `uv run mypy`  
  **Success: no issues found in 38 source files.**
- `uv run pytest -m slow -o addopts= -q`  
  **229 deselected; exit code 5** because this checkout defines no tests marked `slow`.

The resolver and registry reproductions were local Python calls, not HTTP traffic. A first warrant harness attempt used an incorrect import location for `generate_ed25519_keypair` and failed with `ImportError`; it was corrected to import the helper from `actentra_core.checkpoints`, after which the quota replay reproduced.

## Integrated assessment

F-2 through F-5 controls pass their existing focused regression suites in the tested paths, but “integrated” does not mean adversarial combination coverage has been established. In particular, identity spoofing undermines the principal binding assumed by claims, handoffs, and leases when the caller uses structured bearer tokens or the delegation header. No full gateway-to-executor attack was launched; the same authorization defect is evident at the resolver and handler boundary.

The repository’s fast suite is reliability evidence for exercised code, not proof of product security. Several user-requested cases—process interruption, receipt write failure after claim consumption, multi-process database stress, TLS/server integration, and Windows reparse-point races—remain untested.
