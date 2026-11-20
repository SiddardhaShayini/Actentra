# Actentra — Security Review Summary

**Validation date:** 2026-11-20
**Repository state:** `main` at `63e1be8cffce0243a3e87a0aa0b3728f64a963f5`
**Scope:** Independent validation of original findings F-1 through F-5 and residual security risks.

Actentra contains useful local enforcement controls, but it is **not suitable for remote or production security enforcement in this state**. A structured bearer token bypasses the configured gateway secret and can obtain wildcard operator authority. A caller-controlled delegation header grants authority over the named parent. A standalone in-memory warrant registry can also forget an exhausted finite-use warrant.

## Post-remediation findings

| # | Severity | File | Lines | Vulnerability / conclusion | Confidence |
|---|----------|------|-------|----------------------------|------------|
| 1 | 🟠 HIGH | `gateway/actentra_gateway/http_service.py`; `core/actentra_core/identity.py` | 122-147; 220-280, 300-309 | **VERIFIED REMEDIATED (SECOND PASS)** — Structured bearer prefixes no longer bypass configured secrets. Caller-asserted delegation headers without active, registered `DelegationGrant` are strictly rejected. 14 adversarial regression tests pass. | 10/10 |
| 2 | 🟠 HIGH | `executors/actentra_executors/http.py` | 101-170, 178-274, 333-369, 551 | **VERIFIED REMEDIATED** — DNS answers are validated and pinned to the connection; peer and redirect checks and proxy isolation are in place. Focused regression tests passed. | 9/10 |
| 3 | 🟡 MEDIUM | `core/actentra_core/warrants.py`; `core/actentra_core/receipts.py` | 260-290; 2535-2610 | **PARTIALLY REMEDIATED** — SQLite-backed `Boundary` use is durable and atomic, but the standalone memory fallback evicts exhausted quotas at its emergency cap. Finite-use replay was reproduced locally. | 9/10 |
| 4 | 🟡 MEDIUM | `sdk/python/actentra/boundary.py`; `core/actentra_core/receipts.py` | 626-779; 791-825 | **VERIFIED REMEDIATED** — When verification is requested, success is recorded only after a passing observation; refuted and inconclusive outcomes are recorded as failure or unknown. | 9/10 |
| 5 | 🟡 MEDIUM | `gateway/actentra_gateway/services.py`; `core/actentra_core/receipts.py` | 592-817; 2809-2890 | **VERIFIED REMEDIATED** — HTTP outcome reports require a one-time crossing/principal-bound claim. Reports remain `caller_reported`; they do not prove external execution. | 9/10 |

## Validation results

- Five remediation regression suites: **59 passed**.
- Complete fast suite: **228 passed, 1 skipped**.
- Ruff: **All checks passed**.
- Mypy: **No issues found in 38 source files**.
- `pytest -m slow`: no tests marked slow; **229 deselected**, exit code 5.
- No external systems were contacted. No implementation or test source was changed.

## Readiness and next action

Suitable only for local personal use and controlled developer testing with trusted same-host code, noncritical targets, and loopback-only gateway exposure. Controlled alpha use should wait until the identity and quota issues are fixed. Limited production and enterprise production are **not recommended**.

The most important next action is to accept structured identities only through configured credentials and remove caller-asserted delegation, then add HTTP-level regression tests for both reproduced bypasses. An independent external penetration test is justified after those fixes.

## Detailed reports

- [Finding 01 second-pass remediation report](REMEDIATION_REPORT_FINDING_01_SECOND_PASS.md)
- [Post-remediation security validation](POST_REMEDIATION_SECURITY_VALIDATION.md)
- [Finding remediation verification](FINDING_REMEDIATION_VERIFICATION.md)
- [Integrated adversarial test report](INTEGRATED_ADVERSARIAL_TEST_REPORT.md)
- [Residual security risks](RESIDUAL_SECURITY_RISKS.md)
- [Security readiness assessment](ACTENTRA_SECURITY_READINESS_ASSESSMENT.md)
