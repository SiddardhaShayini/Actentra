# Actentra — Finding Remediation Verification

**Assessment date:** 2026-11-20  
**Basis:** Current source at `63e1be8cffce0243a3e87a0aa0b3728f64a963f5`, historical commit diffs, and locally executed tests

## Summary matrix

| Finding | Original vulnerable implementation | Remediation and current enforcement | Tests / independent evidence | Final status | Remaining concerns |
|---|---|---|---|---|---|
| F-1 | Gateway/services trusted caller-asserted agent IDs, with insufficient principal binding and lease ownership checks. See `70b09e8^` and original audit. | `CallerContext`, scopes, token principal mappings, identity claims, and service checks were added. However, `http_service.py:122-147` accepts any `agent:`, `approver:`, or `operator:` bearer prefix; `identity.py:220-280` takes delegation from a request header and adds it to `allowed_agents`. | Identity suite passes (part of 59 targeted tests). Independent resolver calls reproduced both an operator token with wildcard scopes despite a configured secret and a forged parent delegation. | **NOT REMEDIATED** | Remote gateway callers that can reach a remotely bound service can bypass configured bearer authentication and obtain operator authority. Delegation has no verified chain or revocation mechanism. |
| F-2 | URL validation resolved DNS separately from `urllib` socket connection, enabling DNS TOCTOU SSRF. See `95ea272^`. | `http.py:101-170` validates DNS answers and pins a destination; `178-274` connects to that IP and checks the peer; `333-369` validates redirects; `551` disables environment proxies. | DNS rebinding suite is included in the targeted run; all five targeted suites passed (59 total). Tests cover mixed records, private addresses, peer mismatch, redirects, proxy isolation, and TLS hostname behavior. | **VERIFIED REMEDIATED** | Private destinations can be enabled by explicit executor/policy configuration. This is a connector-level control, not process/network sandboxing. No real local HTTP/TLS server was used in this audit. |
| F-3 | `WarrantRegistry` used volatile counters, which reset on restart and could be evicted. See `910f463^`. | `Boundary` links the registry to `ReceiptStore`; `receipts.py:2535-2610` performs SQLite `BEGIN IMMEDIATE` usage updates; `warrants.py:260-290` retains a standalone memory fallback. The fallback forcibly evicts its oldest entry at `2 * max_warrants`. | Quota suite passes as part of 59 tests. Independent bounded reproduction with `max_warrants=2` showed a used finite-use warrant’s remaining quota reset to 1 after eviction, then allowed a second consumption. | **PARTIALLY REMEDIATED** | The normal database-backed Boundary route is materially improved. The standalone fallback still permits replay after enough distinct limited warrants. Multi-process behavior was not independently stress-tested here. |
| F-4 | `Boundary.execute()` persisted success before postcondition verification and suppressed verifier exceptions. See `1cde0f5^`. | `boundary.py:626-779` defers outcome finalization when verification is requested; only `verified` records success / externally verified evidence; `refuted` records failure and other statuses record unknown. `receipts.py` commits observation and outcome together. | Postcondition suite passes as part of 59 tests, including verified/refuted/error/stale/unconfigured cases and atomic observation/outcome persistence. | **VERIFIED REMEDIATED** | External side effects cannot be rolled back if verification fails. With `raise_on_postcondition_failure=False` (default), the raw executor result is returned even when the stored outcome is failure or unknown; callers must inspect the receipt or opt into strict raising. A process crash can leave a decision with no outcome. |
| F-5 | Gateway outcome endpoint accepted arbitrary outcome reports without proving a crossing had been claimed or binding caller identity. See `63e1be8^`. | `claims.py`, `receipts.py:2809-2890`, `services.py:592-817`, and the HTTP claim/outcome routes implement durable, atomic claim issuance/consumption and principal/crossing checks. Outcomes are explicitly `caller_reported`. | Outcome suite passes as part of 59 tests, covering required claims, replay rejection, cross-executor rejection, expiry, disallowed crossings, and HTTP flow. | **VERIFIED REMEDIATED** | Claim binding prevents arbitrary/replayed HTTP reports, but does not attest execution or remote state. Direct in-process service calls with no `caller_context` use an internal compatibility path and are trusted-code-only. |

## F-1 — Identity authentication and delegation

The remediation introduces a useful principal model and scope checks, and ordinary configured token-principal mappings constrain agent IDs. The runtime still has two direct bypasses:

1. `ActentraHTTPHandler._check_auth()` accepts bearer values beginning `agent:`, `approver:`, or `operator:` even when the server has a configured `auth_token` (`gateway/actentra_gateway/http_service.py:122-147`). `resolve_http_caller_context()` then turns `operator:<anything>` into an authenticated operator with `('*',)` scopes (`core/actentra_core/identity.py:300-309`). The unauthenticated string is treated as a credential.
2. `resolve_http_caller_context()` reads `X-Actentra-Delegated-By` directly from request headers (`identity.py:220`) and, for structured/mapped agent strings, appends that value to the caller’s `allowed_agents` (`identity.py:237-238, 267-280`). No signed delegation, parent-issued grant, scope-subset check, chain validation, expiry, or revocation check is performed.

The direct reproduction with a configured shared secret returned `authenticated_operator`, wildcard scope, and `is_trusted_operator=True`. The second reproduction let an authenticated attacker act as the header-named victim. Thus the original trust-boundary defect remains exploitable; the finding is **NOT REMEDIATED**.

## F-2 — DNS rebinding and SSRF

The connection path now connects to the selected validated IP rather than asking the HTTP library to resolve the hostname again. It checks all resolver answers before pinning, validates the actual peer, preserves the HTTPS hostname for TLS, explicitly disables proxies, and revalidates redirect destinations. The dedicated tests are meaningful regression evidence and passed as part of the 59-test targeted run. F-2 is **VERIFIED REMEDIATED** for requests through `ScopedHTTPExecutor` when private-IP access is not explicitly allowed.

This does not isolate arbitrary code running in the same process from direct `socket` or third-party HTTP use. Also, a policy that intentionally sets `allow_private_ips` changes the SSRF boundary and must be treated as trusted configuration.

## F-3 — Warrant quota durability and atomicity

SQLite-backed consumption uses `BEGIN IMMEDIATE`, persists usage across `ReceiptStore` instances, and is automatically bound by `Boundary`. These are meaningful protections for the normal SDK execution path. The current standalone fallback is not safe at its emergency capacity limit: `warrants.py:286-290` deletes the oldest counter when the map reaches twice the configured size, without excluding exhausted finite-use warrants.

The local reproduction used a target `max_uses=1` warrant, consumed it once, added distinct finite-use warrants to force eviction, then successfully consumed the target again. The finding is therefore **PARTIALLY REMEDIATED**. Do not rely on `WarrantRegistry` without a durable store for security-sensitive quota enforcement.

## F-4 — Postcondition and outcome lifecycle

When verification is requested, the code now waits for the verifier result before writing the outcome. A passing observation is required for a `success` / `externally_verified` outcome; refutation becomes `failure`, while error, stale, and missing verifier results become `unknown`. The observation and outcome use a single storage transaction. The core issue is **VERIFIED REMEDIATED**.

The executor side effect may already have occurred when postcondition verification fails. The receipt correctly does not assert verified success, but the default API returns the executor’s raw result unless strict failure raising is enabled. A caller that treats “returned value” as proof of success can still mishandle the action. Crash recovery and an explicit durable dispatched/indeterminate lifecycle were not demonstrated.

## F-5 — External outcome reporting

HTTP routes require a claim, and the storage layer atomically consumes it while checking claim ID, crossing, principal, status, and expiry. HTTP regression tests support replay and cross-principal enforcement. The finding is **VERIFIED REMEDIATED** for the gateway API.

The semantics intentionally stop short of execution attestation: a valid claim permits a caller to submit a caller-reported result, and the receipt marks it `caller_reported`. It must not be elevated to independently verified state. The compatibility path for `caller_context=None` should only be used by trusted in-process code.
