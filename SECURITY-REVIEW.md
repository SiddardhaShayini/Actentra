# Security Review Summary

Date: 2026-11-19

Actentra is an alpha/local-first execution boundary prototype. It should not be placed between autonomous agents and critical business systems until the P0/P1 findings below are remediated and independently retested.

## Confirmed findings

| # | Severity | File | Lines | Vulnerability | Confidence | Status |
|---|----------|------|-------|---------------|------------|--------|
| 1 | 🟠 HIGH | gateway/actentra_gateway/http_service.py; gateway/actentra_gateway/services.py; core/actentra_core/identity.py | 623-685,748-792;161-177;54-129 | HTTP agent, handoff, and lease identities are caller-asserted rather than cryptographically bound to an authenticated principal | 9/10 | **REMEDIATED** |
| 2 | 🟠 HIGH | executors/actentra_executors/http.py | 157-177,294-297 | DNS rebinding/SSRF bypass because validation resolution is separate from urllib connection resolution | 9/10 | **REMEDIATED** |
| 3 | 🟡 MEDIUM | core/actentra_core/warrants.py; sdk/python/actentra/boundary.py | 218-243;180-218,538-552 | Warrant `max_uses` enforcement is process-local, evictable, and reset by restart | 9/10 | **REMEDIATED** |
| 4 | 🟡 MEDIUM | sdk/python/actentra/boundary.py | 605-617 | A success receipt is recorded before postcondition verification, allowing contradictory refuted/error observations | 9/10 | Open |
| 5 | 🟡 MEDIUM | gateway/actentra_gateway/services.py; gateway/actentra_gateway/http_service.py | 521-559;479-507 | External outcome reporting has no execution claim, executor identity, or one-time binding | 9/10 | Open |

## Validation

- Fast pytest suite passed after restoring dev dependencies.
- Ruff passed.
- Mypy passed for 37 source files.
- No implementation files were changed.

## Deliverables

- [ENTERPRISE_SECURITY_AUDIT.md](ENTERPRISE_SECURITY_AUDIT.md)
- [ARCHITECTURE_WEAKNESSES.md](ARCHITECTURE_WEAKNESSES.md)
- [ADVERSARIAL_TEST_PLAN.md](ADVERSARIAL_TEST_PLAN.md)
- [INTEGRATION_READINESS.md](INTEGRATION_READINESS.md)
- [ENTERPRISE_PRODUCT_ASSESSMENT.md](ENTERPRISE_PRODUCT_ASSESSMENT.md)
- [ACTENTRA_NEXT_ROADMAP.md](ACTENTRA_NEXT_ROADMAP.md)
