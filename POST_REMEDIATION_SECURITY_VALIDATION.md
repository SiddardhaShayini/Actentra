# Actentra — Post-Remediation Security Validation

**Assessment date:** 2026-11-20  
**Repository:** `SiddardhaShayini/Actentra`  
**Scope:** Findings F-1 through F-5 and a bounded review of material architecture risks  
**Approach:** Read-only implementation review; local tests and non-network reproductions only

## Executive summary

The five remediation commits are present in the current branch, but the implementation does **not** close every original finding. The gateway still accepts caller-invented structured bearer tokens, including an `operator:` token that resolves to wildcard administrative authority despite a configured shared token. A caller-controlled delegation header also grants authority over the named parent. Separately, a finite-use warrant can be replayed after eviction when `WarrantRegistry` is used without its SQLite store.

The HTTP executor’s DNS pinning, deferred postcondition outcome recording, and claim-bound HTTP outcome reporting are supported by the implementation and regression tests. Those controls have important limits: caller-reported outcomes do not prove external execution, Actentra does not sandbox arbitrary in-process Python, and local receipt integrity is not protection against a host administrator.

| Finding | Final status | Basis |
|---|---|---|
| F-1 — Caller-asserted identity and unauthorized delegation | **NOT REMEDIATED** | Structured tokens bypass configured bearer authentication; a caller-controlled delegation header grants parent identity. |
| F-2 — HTTP DNS rebinding / SSRF | **VERIFIED REMEDIATED** | Resolution is validated and pinned to the socket destination, peer checked, and redirects revalidated; focused regressions pass. |
| F-3 — Warrant quota durability / atomicity | **PARTIALLY REMEDIATED** | SQLite-backed `Boundary` use is durable and atomic; standalone in-memory fallback still evicts exhausted quotas at its emergency cap. |
| F-4 — Premature success before postcondition verification | **VERIFIED REMEDIATED** | Verified success is persisted only after a passing observation; refuted/error outcomes are failure/unknown. |
| F-5 — Unbound external outcome reporting | **VERIFIED REMEDIATED** | HTTP reports require a single-use claim bound to crossing and executor principal; evidence remains caller-reported, not proof of execution. |

These are finding-specific statuses, not a claim that the product is secure or enterprise-ready.

## Scope and methodology

Reviewed the original enterprise audit, all five remediation reports, the current implementations and regression tests, and the historical diffs and pre-remediation code for the affected paths. Checked principal resolution and gateway/service enforcement; HTTP connection creation, redirect handling and IP checks; warrant storage and consumption; action outcome sequencing; execution claim issuance/consumption; filesystem path handling; secret storage; and signed checkpoint behavior.

The existing suite was run as-is. The two newly discovered behaviors were reproduced locally by invoking the identity resolver and the standalone warrant registry. No source, policy, test, or security-setting changes were made. No external systems or public infrastructure were contacted. The application behavior before remediation was inspected through Git history, not executed by checking out or changing repository state.

## Repository state

- Branch: `main`, tracking `origin/main`.
- HEAD: `63e1be8cffce0243a3e87a0aa0b3728f64a963f5` (`fix(security): remediate finding 05 unbound external outcome reporting`).
- Working tree was clean at audit start.
- Original audit `02887cd` and remediation commits `70b09e8`, `95ea272`, `910f463`, `1cde0f5`, and `63e1be8` are in HEAD ancestry.
- The five deliverables in this audit are report files only; application implementation and tests were not changed.

## Validation commands and results

| Command | Result |
|---|---|
| `uv run pytest -m "not slow" -o addopts= -q` | **228 passed, 1 skipped** in 14.62s. |
| `uv run pytest -o addopts= -q tests/unit/test_security_finding_01_identity.py tests/unit/test_security_finding_02_dns_rebinding.py tests/unit/test_security_finding_03_warrant_quotas.py tests/unit/test_security_finding_04_postconditions.py tests/unit/test_security_finding_05_external_outcomes.py` | **59 passed** in 4.65s. |
| `uv run ruff check core executors gateway sdk cli tests` | **All checks passed.** |
| `uv run mypy` | **Success: no issues found in 38 source files.** |
| `uv run pytest -m slow -o addopts= -q` | **229 deselected**, exit code 5 because no tests are marked `slow`; no slow tests ran. |
| `git diff --check 02887cd..HEAD` | Exit code 2: trailing whitespace is reported in Markdown audit/remediation documentation. No implementation whitespace issue was reported by this command. |

The test counts above are actual runs on this checkout. Historical test-count claims in remediation documents were not treated as evidence.

## Independent reproductions

1. **Authentication bypass:** Calling `resolve_http_caller_context` with `expected_token='configured-secret'` and `Authorization: Bearer operator:attacker` returned `principal_type=authenticated_operator`, `authenticated=True`, `scopes=('*',)`, and `is_trusted_operator=True`.
2. **Delegation spoofing:** Calling the resolver with `Bearer agent:attacker` and `X-Actentra-Delegated-By: victim` returned `allowed_agents=['attacker', 'victim']`; `is_agent_allowed('victim')` returned `True`.
3. **Standalone quota replay:** With `WarrantRegistry(max_warrants=2)`, an already-used `max_uses=1` warrant was evicted after adding four other limited warrants. `remaining_uses(target)` changed to 1, and another `record_use(target)` succeeded, changing it back to 0.

These are controlled local method-level reproductions, not attacks against a running remote service.

## Strongest established controls

- The regular `Boundary` path attaches its SQLite `ReceiptStore` to the warrant registry, and SQLite transactions serialize usage updates.
- The HTTP executor validates all DNS answers, pins a chosen address into the connection factory, checks the connected peer, blocks ambient proxies, and revalidates redirects.
- Postcondition outcomes are persisted after verification; only a verified observation creates an `externally_verified` outcome/evidence record.
- HTTP external outcomes require a one-use execution claim associated with the crossing and reporting principal, and distinguish `caller_reported` evidence from independent verification.
- Deterministic policy evaluation and hash-chained SQLite receipts provide useful local enforcement and tamper evidence.

## Important unverified assumptions and limits

- No process-kill test was performed between external side effect and postcondition/outcome persistence. A missing outcome after interruption is not a verified failure or a verified success.
- No multi-process warrant stress, database interruption, disk-full, WAL corruption, or recovery fault-injection test was run in this audit. SQLite is a single-host persistence/concurrency mechanism, not distributed consensus.
- HTTP regressions use simulated DNS/socket behavior; this audit did not run a real local HTTP server or TLS endpoint. No external network endpoint was contacted.
- Windows symlink/junction replacement races were not attempted. The executor checks path containment before path-based file operations; concurrent replacement remains a credible TOCTOU concern.
- No external penetration test, dependency vulnerability scan, SBOM audit, release-signing review, or deployment configuration review was performed.
- Gateway outcomes report what an authorized caller claims. A claim does not attest that the external executor performed the operation or that the remote system reached the claimed state.

## Readiness conclusion

Actentra is appropriate for local, controlled development and noncritical testing with trusted same-host callers and disposable targets. It is **not suitable for remote or production enforcement in this state**: the authentication bypass undermines the gateway boundary, the in-memory warrant fallback can exceed quota, and filesystem/process isolation and independent audit anchoring are not established. See [ACTENTRA_SECURITY_READINESS_ASSESSMENT.md](./ACTENTRA_SECURITY_READINESS_ASSESSMENT.md) for stage-by-stage criteria.

An independent external penetration test is justified after the authentication and delegation defects are corrected, with a controlled scope covering the gateway and executor boundaries. The single most important next action is to remove unauthenticated structured-token acceptance and caller-asserted delegation, then add regressions that exercise those exact cases.
