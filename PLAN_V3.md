<p align="center">
  <img src="assets/actentra-logo-dark.svg" alt="Actentra" width="260" />
</p>

# Actentra V3 — Strategic Product and Engineering Roadmap

> **Scope:** Repository-grounded planning only. This document does not implement the recommendations or claim that tests, builds, or runtime checks were run. Findings below come from static inspection of the current source, documentation, tests, and configuration.

## 1. Executive Summary

Actentra has evolved beyond the Phase 0 description still shown in `PLAN.md`. The repository now contains a substantial local-first Python toolkit: a deterministic policy kernel, SDK and adapters, scoped filesystem/SQLite/HTTP executors, an MCP proxy, CLI, local HTTP gateway and operator console, persistent approval records, audit receipts, simulation, and policy canary tooling. The right V3 direction is **not a rewrite or a larger platform**. It is to make the existing action lifecycle safe, consistent, and demonstrably reliable across the SDK, MCP, and gateway, then make that lifecycle easier for a developer/operator to configure and understand.

The previous `REVIEW.md` correctly identified several serious gaps, but many have since been addressed in source: approved execution now re-checks the verdict and atomically claims the approval; redirects are validated; non-loopback binding requires explicit authorization and a token; the console escapes many dynamic fields; gateway taint and budget hooks were added; SQLite CTE classification is more careful; and HTTP body/receipt query limits were improved. The old review should therefore be treated as a historical snapshot, not as the current issue list.

Important remaining work is more focused:

1. **P0 — Remove implicit approval.** The HTTP approval route currently defaults a missing `approved` field to `true`, and malformed JSON is converted to an empty object. Approval must require a valid, explicit boolean.
2. **P1 — Define trusted execution context and budget semantics.** Gateway callers choose their own session IDs and provenance; budgets and taint are process-local; and externally reported outcomes do not update usage. These details can weaken session-scoped controls.
3. **P1 — Make canary replay faithful before using it as a release gate.** Current replay rebuilds actions without provenance and does not preserve historical timing, so taint-, rate-limit-, or budget-dependent comparisons can be misleading.
4. **P1 — Close audit concurrency and context-integrity gaps.** External outcome duplicate detection is a check followed by a separate append, and stored envelope context is not itself covered by the receipt hash chain.
5. **P2 — Clarify product claims and supported operating modes.** The product-status document is useful, but “supported” must mean tested end-to-end for each claimed guarantee. Remote binding is token-protected but served over plain HTTP; the local-first service should not be presented as a secure remote control plane.

A unified lightweight application is feasible and largely exists as the embedded local web console backed by `AppServices`. The product opportunity is to finish that experience as an operator surface over the same policy and execution lifecycle—not to add a desktop shell, cloud control plane, or general-purpose agent builder. Keep the Python SDK and CLI as first-class interfaces.

## 2. Current Project State

### What is implemented

| Area | Current repository evidence | Assessment |
|---|---|---|
| Authorization kernel | `core/actentra_core/policy.py`, `envelope.py`, `canonicalize.py`, `budgets.py` | Deterministic YAML policy evaluation, action canonicalization, risk/context handling, rate limits, and cumulative budgets form a coherent core. |
| Durable audit | `core/actentra_core/receipts.py` | SQLite WAL decision/outcome receipts, hash chaining, persisted action envelopes, approval records, bounded query APIs, and recovery helpers are present. |
| Developer integrations | `sdk/python/actentra/`, `gateway/actentra_gateway/mcp_proxy.py` | In-process `Boundary`, function-calling/LangChain adapters, and MCP stdio mediation provide multiple integration paths. The actual enforcement guarantees still need path-specific acceptance tests. |
| Scoped actions | `executors/actentra_executors/` | Filesystem, SQLite, and HTTP executors constrain the first-party execution surface. These are not OS isolation and cannot protect calls that bypass Actentra. |
| Operator workflow | `gateway/actentra_gateway/services.py`, `http_service.py`, `console.html` | Shared application services, persisted approvals, optional executor dispatch, a local REST API, and an embedded multi-view console exist. |
| Operations and policy tools | `cli/actentra_cli/main.py`, `core/actentra_core/canary.py` | CLI setup/checking, dry-run, replay/canary, receipts, reports, checkpoints, and warrants are available in some form. Some features remain primitives rather than fully integrated controls. |
| Engineering foundation | `tests/`, `spec/`, `policies/`, `pyproject.toml` | The repository has unit, integration, property, replay, and performance test areas plus strict lint/type-check configuration. This plan does not independently execute or verify them. |

### Product maturity and boundary

The codebase is best treated as a **feature-rich alpha/prototype**: it has useful and distinctive engineering foundations, but its security and operational guarantees need to be established across every supported path before production reliance. Actentra mediates only calls routed through it; it does not replace operating-system/cloud IAM or protect against a fully compromised host. The project’s own `docs/guarantees-and-limits.md` states these limits.

The target audience should remain Python developers and technical operators building agents that use tools, especially local or MCP-based workflows. The repository alone cannot establish customer demand, deployments, willingness to pay, or commercial viability.

## 3. Validated Findings From `REVIEW.md`

The previous review is useful context, but several findings are stale. This table distinguishes verified remediations from issues that remain or need tighter qualification.

| Previous finding or claim | Current source assessment | V3 implication |
|---|---|---|
| Approved crossing could execute without checking the new policy decision or could be dispatched twice. | **Substantially addressed.** `AppServices.execute_approved_crossing()` checks `decision.verdict.permits_execution` and calls the atomic `ReceiptStore.claim_approval_for_execution()` before dispatch. Expiry cleanup includes approved records. Keep regression tests for policy changes, expiry, races, and dispatch failure. | Do not carry this forward as an open confirmed bypass; preserve it as a lifecycle invariant and test requirement. |
| HTTP redirects could bypass destination validation. | **Addressed in the inspected implementation.** `ScopedHTTPExecutor` installs `SSRFSafeRedirectHandler`, validates each redirect target, and limits redirects. | Keep adversarial redirect regression tests; do not describe the old issue as current. |
| Remote gateway binding did not require a token. | **Addressed in configuration checks.** `ActentraHTTPServer` refuses non-loopback binding without explicit remote authorization and a non-empty token. The service is still plain HTTP, so a bearer token is not protected in transit on an untrusted network. | Keep loopback as the supported default. Do not equate the unsafe remote flag plus token with a production remote mode; require TLS termination/tunnel and a documented threat boundary before any remote support claim. |
| Approval UI rendered untrusted data into HTML. | **Broadly addressed.** The current console uses `escapeHtml()` for the approval fields, parameters, tables, errors, and other dynamic strings; HTML responses add CSP, `nosniff`, and frame denial headers. | Preserve contextual output encoding and add browser-facing regression checks. Avoid embedding raw data in HTML/JavaScript contexts. |
| Gateway taint propagation and cumulative budget recording were absent. | **Partially addressed.** `submit_crossing()` inherits and records in-process session taint; `_dispatch_and_record()` records budget usage after successful gateway executor dispatch. Caller-supplied session IDs/provenance remain trust inputs, state is in memory, and `record_external_outcome()` does not update budget usage. | Define identity, trust, and usage semantics across SDK, gateway, and external-executor paths; do not claim durable/session-wide enforcement until those semantics are implemented. |
| SQLite CTEs were all treated too permissively as reads. | **Addressed in the inspected code.** `sqlite.py` scans through CTEs to identify the main statement, and read-only connections use SQLite `query_only`. | Keep tests for nested/multiple CTEs, comments, and mutating statements; continue to fail closed on ambiguous SQL. |
| External outcome reports could be duplicated or attached to a non-allowed decision. | **Partially addressed.** The service checks that a decision exists, permits execution, and has no prior outcome. Those checks and the append are separate operations, so concurrent requests can still race. The reporter’s assertion is not independent proof of execution. | Make the invariant transactional/unique and label external outcomes as caller-reported unless authenticated evidence is added. |
| Receipt query limits and negative request sizes were unbounded. | **Mostly addressed.** Receipt limits are clamped to 1–500; offsets are clamped at zero; request bodies reject negative and oversized lengths. Very large offsets/search terms and full-log operations still need an explicit resource strategy. | Keep bounded queries, and set limits for input strings, exports, replay, and retained history where appropriate. |
| Dry-run could consume rate-limit capacity; policy export omitted fields; health verification was expensive. | **Addressed in the current code paths.** Evaluation exposes `record_rate_limit=False` for simulation, policy export includes limits/budgets/match fields, and ordinary health checks use latest/count rather than full chain verification. | Preserve side-effect-free simulation and distinguish fast health from integrity verification. |
| Receipt-search test had a vacuous `or True` assertion. | **No longer present in the inspected `tests/unit/test_app_services.py`.** The current assertion checks that the retrieved envelope contains the searched resource. | Do not repeat this as a current test defect; continue checking assertions for meaningful outcomes. |
| Hash display claimed RFC 8785 canonical JSON. | **Still mismatched.** `console.html` labels the hash format RFC 8785, while `canonicalize_json()` uses Python `json.dumps(sort_keys=True, separators=..., ensure_ascii=False)`. That implementation is deterministic for its supported values but is not evidence of RFC 8785 conformance. | Correct the label or implement and validate the claimed standard with cross-language test vectors. Do not imply interoperability without evidence. |
| Policy canary provides verified replay fidelity. | **Not established by current source.** `run_policy_canary()` reconstructs envelopes from action/agent fields but omits stored provenance and intent. It also evaluates historical actions in sequence using current engine state rather than their recorded timestamps, so taint, rate limits, and budgets may be replayed inaccurately. | Treat canary output as advisory until context completeness and temporal semantics are explicit and tested. |
| Approval API has strict explicit approval semantics. | **A remaining high-risk gap.** In `http_service.py`, malformed approval JSON is swallowed into `{}`, then `approved` defaults to `True`; a valid empty JSON object has the same effect. | P0: require a parseable object with an explicit JSON boolean and reject all missing/wrongly typed values. |

### Additional validated gaps

- **Caller-controlled session context:** `AppServices.submit_crossing()` accepts `session_id`, `agent_id`, and provenance from request data. Session budgets and taint use the session ID; no gateway-side authenticated identity/session registry is evident in the inspected path. A caller can therefore select a fresh session key or claim context unless the deployment supplies a trusted wrapper.
- **Taint and budget persistence:** `Boundary` stores taint in an in-memory map and `PolicyEngine`/`SessionBudgetTracker` retain bounded process-local state. Process restart can reset this state. Persisted approval records do not make budgets or taint durable.
- **External execution accounting:** An allowed crossing may be submitted without gateway execution and later receive an external outcome. That reporting path does not call `budget_tracker.record_usage()`. The budget behavior for external execution is therefore not equivalent to registered executor dispatch.
- **Dry-run session argument:** `AppServices.simulate_dry_run()` accepts `session_id`, but does not pass it to `Boundary.dry_run()`. The simulation can evaluate under the Boundary’s configured session rather than the requested session and does not inherit that requested session’s taint.
- **Warrant and secret integration:** Warrant utilities exist, but the inspected SDK `Boundary` execution path does not enforce a warrant as part of each action authorization. A SecretsBroker exists, but an end-to-end credential-reference flow is not established by the inspected HTTP executor; its `secret_headers` constraint accepts values directly. Mark these capabilities according to proven end-to-end coverage, not just module presence.
- **Audit context binding and scalability:** Receipt hashes cover receipt fields; the separately stored `action_envelopes` row is written atomically with a decision, but its contents are not included in the hash-chain entry. `verify_log()` does not by itself prove the envelope table was not altered. Full verification, export, and canary paths materialize receipt records in memory.
- **Documentation drift:** `docs/product-status.md` and `docs/lifecycle-contract.md` provide valuable recent contracts, but `PLAN.md` and the opening status in `PROJECT_MEMORY.md` still say Phase 0. `README.md` and the product-status matrix also make broad “supported” claims that should be tied to end-to-end evidence. The stale Phase 0 criticism in `REVIEW.md` is partly superseded by newer documents, but the repository still has conflicting status sources.

## 4. Long-Term Vision

Make Actentra the **small, dependable local authorization and evidence layer for agent tool use**:

> An agent proposes an action; Actentra applies a human-readable deterministic policy, obtains narrowly scoped approval when needed, dispatches only through an explicitly configured executor, and records what was decided and what outcome was reported.

The differentiator should be trustworthiness and ease of adoption, not a large number of connectors. A user should be able to answer, for every supported action: who submitted it, what context was trusted, which policy decided it, whether a human approved it, what exact executor ran, and whether the outcome is confirmed, failed, or unknown.

### Product direction

- **Primary users:** Python agent developers and local technical operators who need deterministic controls and local auditability.
- **Secondary users:** Small teams evaluating MCP-mediated tools and local workflows with sensitive files or data.
- **Not the initial target:** General consumers, multi-tenant enterprise security teams, or organizations seeking a hosted governance control plane. The current repository does not establish operational support or market demand for those buyers.
- **Adoption proposition:** Integrate without replacing the agent framework; start with a narrow policy; inspect why actions were allowed/blocked; retain local records; use the SDK/CLI or the operator console as appropriate.

### Is a unified application worthwhile?

Yes, as a **single local operator surface over existing shared application services**. The current `AppServices` and embedded `console.html` already make this technically feasible. Improve it in small steps: setup/status, action and approval review, dry-run/canary, receipt verification, and clear execution outcomes. Preserve the underlying YAML, SDK, CLI, and MCP flows. The UI should not become a second authorization engine or imply that “approved” means “executed.”

The UI alone does not improve security. It can reduce setup friction, but a polished approval inbox can increase approval fatigue. Approval screens should show exact action context, policy reason, provenance/trust, constraints, expiry, and current lifecycle state; require an explicit action; and avoid bulk approval.

## 5. Existing Features — Keep, Improve, or Replace

| Capability | Decision | Rationale and approach |
|---|---|---|
| Deterministic core, deny-by-default policies, canonical action envelope | **Keep; strengthen contracts** | This is the core value and a sound reason to retain the current modular Python architecture. Clarify which envelope context is security-relevant and bind it to the decision/approval record. |
| SDK, CLI, MCP proxy, HTTP gateway | **Keep; unify semantics** | These are useful integration choices, but each must meet one lifecycle contract for identity, authorization, approval, dispatch, failure, and receipts. Avoid separate policy implementations. |
| Filesystem, SQLite, HTTP executors | **Keep narrow; harden and document limits** | These provide useful reference integrations. Make executor constraints explicit and test their real boundary behavior. Do not expand connector count until the lifecycle contract is stable. |
| SQLite WAL receipts and approvals | **Keep; improve integrity and retention model** | SQLite fits local-first use. Bind action context to the logged decision, make outcome uniqueness atomic, and define retention/export behavior before large logs become normal. |
| Local operator console | **Improve incrementally** | Use `AppServices`; improve clear state transitions, setup guidance, accessibility, and error visibility. Do not add a separate frontend build system or desktop wrapper without adoption evidence. |
| Canary, replay, dry-run | **Keep; qualify until faithful** | These are high-value developer tools, but should not act as release gates until they model the same inputs and temporal limits as live evaluation. |
| Warrants and SecretsBroker | **Integrate or relabel experimental** | The primitives may be valuable, but users need an end-to-end authorization/credential workflow before interpreting them as active enforcement. Keep secret values out of policies, envelopes, logs, and the UI. |
| Remote binding | **Constrain; do not productize yet** | A token gate is present, but the built-in server is plain HTTP and caller identity/context semantics are incomplete. Keep the supported posture local-only; remote access requires a separately threat-modeled TLS-protected deployment design. |
| Overall architecture | **Do not rewrite** | The current layers—core, SDK/adapters, executors, gateway/services, CLI—are appropriate for the project’s scale. Extract shared lifecycle helpers only where duplication produces verified divergence. |

## 6. Missing Features and New Opportunities

Complexity and practical value are relative assessments, not evidence of customer demand.

| Feature / capability | User problem and value | Target users | Complexity | Practical value | Priority | Prerequisites and approach |
|---|---|---|---|---|---|---|
| Strict approval API contract | Prevent accidental approval from missing, malformed, or mistyped request data. | All gateway users | Low | High | **P0** | Require `approved` as a JSON boolean; reject malformed/missing values; add endpoint-level regression coverage. |
| Trusted gateway identity/session model | Prevent caller-selected session IDs from silently defining taint/budget scope; make provenance authority explicit. | Gateway/MCP operators | High | High | **P1** | Decide local trust model first. Bind sessions to authenticated client identity or trusted adapter state; bound session creation and persistence; treat caller-declared provenance as untrusted unless attested. |
| Consistent budget accounting | Ensure registered and externally executed actions have defined, non-resettable usage semantics. | Developers and operators | Medium | High | **P1** | Specify whether budgets reserve at authorization or consume at execution, how failures/unknowns count, and how external outcomes are trusted. Apply consistently and atomically. |
| Faithful policy canary | Help policy owners identify genuine permission changes rather than artifacts from missing context or replay order. | Policy authors | High | High | **P1** | Replay provenance, agent/context fields, policy version, and historical timestamps; define handling for missing data; model rate windows and cumulative budgets; show fidelity warnings and excluded records. |
| Atomic outcome recording | Prevent two concurrent reports from creating conflicting outcome receipts. | Gateway and external runners | Medium | High | **P1** | Use a transaction or uniqueness invariant covering one outcome per crossing; test concurrent reports. Identify external outcomes explicitly as caller-reported. |
| Integrity-bound action context | Make receipt verification meaningful for the stored action needed by approvals, audit, and replay. | Auditors and operators | Medium | High | **P1** | Include a context digest or the canonical envelope bytes/hash in the decision record and verify it on retrieval/replay; preserve compatibility through a versioned receipt format. |
| Supported-feature evidence matrix | Help users distinguish usable paths from low-level primitives. | New adopters and maintainers | Low | High | **P1** | For each claim in README/product status, link an end-to-end test or label it experimental/planned; make one status document authoritative. |
| Guided local setup and policy preview | Reduce YAML/tool-name setup errors without hiding policy decisions. | New Python developers/operators | Medium | Medium–High | **P2** | Add a short console workflow that selects an integration, creates a scoped ordinary YAML example, previews decisions, and offers CLI/SDK instructions. |
| Audit retention and bounded export | Keep local audit useful as records grow and avoid memory spikes. | Long-running local installations | Medium | Medium–High | **P2** | Define retention, redaction, export size behavior, and optional checkpoint anchoring; stream or page operations if measurements justify it. |
| Cross-language canonicalization contract | Avoid claiming interoperability based on a Python-specific serializer. | Integrators | Medium | Medium | **P2** | Either correct the RFC 8785 label or implement it; publish test vectors for supported JSON values and verify across implementations. |
| New connectors, hosted control plane, native desktop packaging | Could broaden reach but increases attack surface and support burden. | Unknown | High | Unknown | **P3 / defer** | Do not start without user evidence, stable executor contracts, and an explicit security/maintenance owner. |

## 7. Technical and Architectural Improvements

### What should remain

- Keep the deterministic policy kernel separate from I/O, UI, and framework-specific code.
- Keep first-party executors narrow and policy-constrained; preserve the option to use the SDK without the web UI.
- Keep SQLite and a local embedded server for the single-user/local-first use case.
- Keep policy as ordinary, inspectable YAML and retain a CLI path for automation.

### What should improve

1. **One authoritative lifecycle service.** Define the state machine once and route SDK, MCP, and HTTP gateway behavior through shared lifecycle operations. The existing `AppServices` is a useful starting point, but avoid semantic drift between `Boundary.execute()`, gateway dispatch, approval continuation, and external outcome recording.
2. **Authorization context must be explicit.** Distinguish trusted identity and adapter-attested provenance from caller-supplied fields. Define whether provenance, policy version, constraints, and session scope are part of approval binding. Preserve the action hash’s role, but bind decision context separately if adding it would change the action-hash contract.
3. **Budget and taint lifetime must be specified.** Decide whether these are per-process, per-client, or durable per-session. If the gateway is meant to provide persistent session controls, persist or reconstruct that state and define expiry, quotas, and cleanup. Otherwise clearly describe reset-on-restart semantics and avoid presenting budgets as durable safeguards.
4. **Audit integrity must include replay inputs.** Ensure stored action context can be verified against a receipt. Track replay completeness, event time, and policy inputs. A valid hash chain over receipt rows is useful tamper evidence, but it does not by itself anchor the database against full-host modification or deletion.
5. **Treat errors and unknown outcomes distinctly.** Keep “approved,” “claimed,” “executed,” and “outcome recorded” as separate states. A crash or uncertain external report should remain unknown rather than being presented as success. Define retry/idempotency behavior before adding automatic retries.
6. **Bound work at service boundaries.** In addition to existing request-body and page-size caps, set defensible limits for search strings, canary input/record count, exports, pending approval lists, and session state. Add streaming/paging only where measured data volume requires it.
7. **Make security claims testable.** Map each invariant in `docs/guarantees-and-limits.md` and `docs/lifecycle-contract.md` to an end-to-end regression test for every supported integration. Keep adversarial tests for malformed inputs, replay context, redirects, concurrent approvals/outcomes, restarts, and unauthorized execution.

### What to redesign only if evidence requires it

- **Do not move to microservices, PostgreSQL, a plugin marketplace, or a cloud control plane** for a single-user local product.
- **Do not rewrite the kernel in Rust** without measured performance or isolation requirements that Python cannot meet.
- **Do not add an elaborate UI framework** while the existing embedded UI is sufficient; first test whether setup and action review are actual adoption blockers.
- Consider a distinct remote service only after user demand, threat model, transport security, identity, authorization, tenancy, operational ownership, and support requirements are defined.

## 8. Real-World Product Strategy

### Usage scenarios

- A Python developer limits an agent to a project workspace and records each read/write decision.
- A local data assistant submits SQLite actions under read-only/row constraints and keeps a reviewable receipt trail.
- An MCP operator mediates tools through the stdio proxy and detects a changed server tool definition.
- A developer tests a policy change against recorded actions before using it.
- A local operator reviews actions requiring human approval and inspects a verified receipt export.

These are plausible repository-supported workflows, not evidence of existing customers or deployments.

### Alternatives and differentiation

The repository names adjacent work such as AARM, AgentBound, ClawLess, and AgentGuardian in `PLAN.md`; `REVIEW.md` also lists broader guardrail and agent SDK projects. These are not necessarily feature-for-feature substitutes. Teams may instead use application-specific checks, standard IAM, framework guardrails, or MCP-specific mediation. The source does not establish comparative performance, security, adoption, or superiority.

Potential differentiators worth testing with users:

- Local-first storage and operation without a hosted control plane.
- A deterministic policy boundary that is separate from LLM output.
- Python/MCP entry points with shared policy and audit concepts.
- A small set of useful first-party scoped executors and human approval.

### Adoption and business conditions

Adoption depends on friction and trust: installation, policy authoring, accurate tool/resource mapping, clear denial reasons, and reliable receipts. The project should first demonstrate value in a narrow local developer workflow. An open-source distribution is the lowest-risk strategy while product fit is unknown. Paid support or team features should be considered only after users request them. SaaS or per-seat monetization is not justified by repository evidence and conflicts with the current local-first emphasis unless the product direction deliberately changes.

## 9. Prioritized Improvement Backlog

| Priority | Work item | Why now | Completion evidence |
|---|---|---|---|
| **P0 — Critical** | Require explicit, well-typed approval decisions at every API/UI boundary. | A missing/malformed request must never grant authorization. | Empty, malformed, missing-field, string-valued, and invalid approval payloads are rejected; only explicit `true` approves and explicit `false` rejects. |
| **P0 — Critical** | Lock the execution lifecycle contract and add regression coverage around the existing re-evaluation/atomic-claim fix. | Authorization correctness is the product’s core promise; recent fixes must remain protected. | Tests prove denied/held/revoked/expired approvals cannot dispatch; concurrent continuation causes at most one dispatch; durable decision precedes dispatch and outcomes are recorded. |
| **P1 — High** | Define trusted gateway identity, session IDs, and provenance authority. | Current request data can choose the keys used for session-scoped controls. | Security contract, validation rules, and tests demonstrate caller cannot silently reset a protected session’s taint/budget scope. |
| **P1 — High** | Make budgets and taint consistent across successful, failed, pending, and externally executed actions. | Gateway and SDK paths currently have different accounting and restart behavior. | Documented lifecycle semantics; matching tests for SDK, gateway executor, external outcome, restart, and duplicate submission. |
| **P1 — High** | Correct canary replay context and time semantics. | Incomplete replay can produce false confidence or false alerts. | Fixtures containing taint, time-separated rate-limited actions, cumulative budgets, and missing context produce expected results and visible fidelity status. |
| **P1 — High** | Make outcome uniqueness and envelope-context integrity verifiable. | Audit value depends on consistency under concurrency and on trustworthy replay inputs. | Concurrent external outcomes yield at most one accepted record; altered context is detected or explicitly reported as unverifiable. |
| **P1 — High** | Reconcile README, status matrix, lifecycle contract, `PLAN.md`, and project memory. | Conflicting maturity/support claims undermine onboarding and security expectations. | One authoritative status source; every “supported” claim links to representative end-to-end evidence or is relabeled. |
| **P2 — Medium** | Add guided setup and explainable policy preview to the local console. | Reduces onboarding friction after core semantics are stable. | A first-time developer can choose SDK/MCP/gateway, create a narrow policy, preview allow/deny/ask, and export standard YAML. |
| **P2 — Medium** | Establish audit retention, privacy, and large-log behavior. | Local logs can contain sensitive action parameters and grow indefinitely. | Documented retention/redaction controls; bounded-memory export/verification behavior measured on representative data. |
| **P2 — Medium** | Correct or implement the claimed canonical JSON standard. | Prevents misleading cross-language compatibility claims. | UI/docs match implementation; canonicalization vectors pass for supported inputs across any claimed runtimes. |
| **P3 — Low** | Evaluate new connectors, desktop packaging, or team/hosted features. | Adds maintenance and security surface without evidenced demand. | Proceed only after user interviews, measurable need, and an owner for ongoing support. |

### Cost of deferring the major recommendations

- **Explicit approval validation (P0):** leaves a direct route from an empty or malformed request to an approved crossing; this is unacceptable even for an alpha.
- **Lifecycle regression tests (P0):** allows future changes to undo the already-added verdict re-check or atomic claim without detection, undermining the central authorization guarantee.
- **Trusted identity, taint, and budget semantics (P1):** leaves session-scoped controls dependent on caller-selected keys and process lifetime; users may believe they have stronger cross-request or restart protection than the implementation provides.
- **Canary replay fidelity (P1):** makes policy comparisons liable to false regressions or missed ones when provenance, rate windows, or budgets matter; using it as a rollout gate before fixing this could create unsafe policy changes.
- **Atomic outcomes and integrity-bound context (P1):** leaves ambiguous audit records possible under concurrency and replay conclusions dependent on context that the receipt chain does not authenticate.
- **Status/document alignment (P1):** continues to mislead new users about what is integrated and validated, increasing support burden and risking reliance on unverified controls.
- **Onboarding and audit scale (P2):** slows adoption and makes long-running local use less manageable, but does not justify delaying core security work.

### Quick wins

- Make the approval boolean mandatory and strictly typed.
- Correct the RFC 8785 label or remove the claim.
- Mark canary results as incomplete/advisory when provenance or temporal context is missing.
- Fix `simulate_dry_run()` to use its supplied session context and test taint inheritance.
- Replace broad silent UI fetch catches with visible, actionable connection/status errors where that improves operator understanding.
- Correct stale phase/status references and label primitives versus end-to-end supported workflows.

### Postpone or avoid

- Do not add more first-party connectors before the executor and lifecycle contract is stable.
- Do not add a remote team control plane, SSO, multi-tenancy, centralized database, or plugin ecosystem for the current local-first target.
- Do not describe the receipt chain as immutable/tamper-proof against host administrators; it is local tamper evidence unless externally anchored.
- Do not use canary output as an automated deployment gate until replay fidelity is validated.
- Do not expose secrets in policy constraints, API responses, logs, envelopes, or approval views.
- Do not build a hosted control plane, multi-tenant service, SSO, or remote team administration as part of the local-first product unless user requirements and ownership explicitly change.

## 10. Phased Development Roadmap

### Phase 1 — Foundation

**Objectives:** Close authorization ambiguities; state the supported local trust model; protect lifecycle invariants.

**Tasks and deliverables**
- Require explicit approval payload fields and strict type validation at the HTTP route.
- Review every control endpoint for default-allow behavior, malformed-input handling, and visible failure responses.
- Preserve and expand tests for approved execution re-evaluation, TTL, policy changes, concurrent claims, executor failures, and durable receipts.
- Define session identity and provenance authority for SDK, MCP, and gateway; document what local callers can assert.
- Specify whether the supported product is strictly single-user/loopback and how the explicit remote flag is treated.

**Why / dependencies:** This is the prerequisite to trusting the rest of the product. It depends only on the current service, boundary, receipt store, and test structure.

**Priority:** P0.

**Expected outcome:** No accidental approval path; one documented local trust boundary; protected authorization/approval invariants.

**Completion criteria:** Negative approval cases reject; no test path can dispatch without a current execution-permitting decision and valid one-time approval where required; the documented service mode matches actual configuration.

### Phase 2 — Core Product Development

**Objectives:** Make the primary developer/operator workflow coherent and consistent.

**Tasks and deliverables**
- Unify lifecycle semantics across `Boundary`, `AppServices`, MCP, and external outcome reporting.
- Define budget consumption/reservation and taint lifetime, including failed, pending, external, and restarted sessions.
- Correct dry-run to honor requested session/provenance and remain side-effect-free.
- Improve the console’s action detail: provenance/trust, policy version/reason, constraints, expiry, and distinct approval/execution/outcome states.
- Ensure that external outcome routes clearly identify caller-reported evidence and reject duplicate/conflicting reports atomically.
- Reconcile setup instructions and feature status with implemented paths.

**Why / dependencies:** Once foundation semantics are stable, the project can reliably tell users what an action means. Depends on Phase 1’s identity and lifecycle decisions.

**Priority:** P1.

**Expected outcome:** A developer can submit, inspect, approve, execute or externally complete, and audit an action without ambiguity about its state or trust context.

**Completion criteria:** End-to-end tests exercise SDK, MCP, gateway executor, approval UI/API, and external outcome routes using the same lifecycle expectations; budgets and taint behave as documented.

### Phase 3 — Advanced Capabilities

**Objectives:** Make policy changes safer and improve the local product experience without broadening the platform prematurely.

**Tasks and deliverables**
- Make canary replay preserve all policy-relevant context and historical timing; show missing-context counts and fidelity limitations.
- Add guided local setup/policy preview using ordinary YAML and existing shared services.
- Integrate warrants into a clearly defined supported authorization path, or label them experimental; specify delegation identity, scope, expiry, and use accounting.
- Define a broker-backed secret reference mechanism for executors, or keep secrets integration explicitly out of the supported workflow.
- Add audit retention/redaction configuration and optional external checkpoint anchoring only where users need it.

**Why / dependencies:** These features are valuable once the core controls are dependable. Canary work depends on Phase 2’s canonical context; warrants/secrets depend on identity and executor contracts.

**Priority:** P1 for faithful canary; P2 for guided UX; P2/P3 for warrants, secrets, and anchoring depending on demonstrated use.

**Expected outcome:** Users can safely preview policy changes and configure core use cases with less repository-specific knowledge.

**Completion criteria:** Canary test fixtures prove context/time fidelity; setup produces policies that pass the same validator and are inspectable; any “supported” warrant/secret flow has end-to-end tests.

### Phase 4 — Production Readiness

**Objectives:** Establish measurable operational and security confidence for the explicitly supported deployment mode.

**Tasks and deliverables**
- Build an invariant-to-test matrix and run the relevant full CI suite in the project’s supported environment; expand platform testing only where support is claimed.
- Test restart/recovery, concurrent approvals and outcomes, bounded inputs, large receipt histories, HTTP redirects, and local browser-origin behavior.
- Establish audit retention, privacy, backup, restore, and export behavior; clearly explain local-chain limitations.
- Remove or qualify the RFC 8785 claim; add canonicalization vectors for any interoperability promise.
- Document installation, first run, policy authoring, failure recovery, supported integrations, and remote-mode limitations.
- Measure gateway startup/idle memory, policy/receipt latency, query/export memory, and practical limits; publish targets only after baselines.
- Keep remote binding disabled or unsupported for production until TLS, authenticated client identity, and remote threat model are implemented and reviewed.

**Why / dependencies:** Production readiness is an evidence claim, not a feature. It depends on lifecycle and trust semantics from Phases 1–3.

**Priority:** P1 for verification and documentation; P2 for improvements driven by measured limits.

**Expected outcome:** An honest alpha/beta release with reproducible evidence, operational guidance, and explicit boundaries.

**Completion criteria:** Every supported guarantee maps to passing tests and documented residual risk; no unsupported deployment mode is implied by README or UI.

### Phase 5 — Long-Term Growth

**Objectives:** Expand only in response to demonstrated user needs.

**Possible tasks**
- Add a connector only when an identified user workflow cannot be served by current executors and the connector can meet the common contract.
- Consider a desktop installer only if users struggle with the local web/CLI model and packaging can remain lightweight.
- Consider team collaboration or remote management only after requirements establish identity, authorization roles, tenancy, transport security, audit ownership, and operational support.
- Publish stable API/schema versions and a compatibility policy if external integrations depend on them.
- Develop ecosystem examples and integrations based on actual adoption rather than speculative breadth.

**Why / dependencies:** Premature platform expansion multiplies threat surface and maintenance cost. Depends on stable core behavior and evidence of repeated use.

**Priority:** P3 until validated demand exists.

**Expected outcome:** Growth that strengthens the core authorization/audit value rather than diluting it.

**Completion criteria:** Each expansion has a named user problem, maintainer, security review, compatibility plan, and measured adoption/operational value.

## 11. Risks and Mitigation

| Risk | Impact | Mitigation |
|---|---|---|
| Approval route or another API path defaults to permissive behavior | Unauthorized or accidental action approval | Require explicit typed inputs; default to rejection; test malformed/empty requests at the HTTP boundary. |
| Caller-controlled session/provenance weakens taint and budgets | Policy decisions may reflect untrusted claims or reset scopes | Define trusted identity sources, bind session scope to that identity, and treat declared provenance as untrusted absent attestation. |
| Process-local counters reset on restart or evict active sessions | Rate/budget controls may not match user expectations | Specify reset semantics; persist only if required by the product; expose limits and state clearly; bound durable storage. |
| Inaccurate canary replay gives false confidence | Risky policy changes may be accepted or safe changes rejected | Preserve full replay inputs and timestamps; report incomplete records; do not use as a hard gate until validated. |
| Receipt chain is mistaken for proof against host compromise | Users overestimate forensic integrity | State that local hash chaining is tamper-evident, not an external trust anchor; offer signed/off-host anchoring as a separate optional measure. |
| Plain HTTP remote use exposes bearer tokens and control actions | Credentials/control plane can be observed or manipulated in transit | Treat gateway as loopback-only by default; require TLS-protected fronting and a threat-modeled identity layer before remote support. |
| Broad product claims outpace integrated tests | User trust and security claims become unreliable | Maintain an authoritative support matrix tied to end-to-end tests; label experimental primitives accurately. |
| Feature expansion exceeds maintenance capacity | More unreviewed code and slower security fixes | Limit scope to core workflows; add features only with user evidence and an explicit maintenance owner. |
| Approval UI causes fatigue or misinterpretation | Operators approve without understanding or mistake approval for execution | Show exact action, trust context, policy rationale, expiry, and execution state; avoid blanket approvals. |
| Audit records expose sensitive parameters | Local database/export may contain secrets or private data | Minimize recorded data where possible; redact secret references; document permissions, retention, and export handling. |

## 12. Success Metrics

The repository does not provide verified adoption or operational baselines. The targets below are **suggestions**, to be measured and adjusted—not claims about current performance.

| Metric | Suggested initial measure/target | Purpose |
|---|---|---|
| Approval safety | 100% of malformed, empty, missing-field, or wrong-type approval requests reject; only explicit boolean `true` approves. | Proves fail-closed route behavior. |
| Lifecycle enforcement | 100% of tested denied/held/expired/revoked crossings have zero executor dispatches; concurrent approval continuation dispatches at most once. | Validates the central security invariant. |
| Cross-path consistency | Identical policy-relevant inputs produce equivalent decisions in SDK, MCP, and gateway paths, except documented adapter differences. | Prevents integration-specific authorization drift. |
| Budget/taint fidelity | Tests cover gateway executor and external execution, session changes, restart, failures, and untrusted provenance; all match the written semantics. | Makes session-scoped controls credible. |
| Canary fidelity | Every replay result states whether context is complete; known fixtures for provenance, rate windows, and budgets match expected diffs. | Prevents overreliance on misleading replay. |
| Audit uniqueness/integrity | No crossing accepts more than one outcome; alteration of decision-linked action context is detected or reported. | Improves audit reliability. |
| Performance | Establish p50/p95 policy evaluation, receipt append/query, gateway start/idle memory, and export memory baselines before setting release SLOs. | Avoids unsupported speed/footprint claims. |
| Onboarding | Observe a small group of target developers completing install → scoped policy → dry-run → first mediated action; track time and failure points. | Tests whether unified UX solves a real barrier. |
| Support-claim coverage | Every capability labeled “Supported” links to at least one maintained end-to-end test or explicit acceptance criterion. | Aligns product language with evidence. |
| Adoption | Track opt-in project usage, repeat usage, issues, and contributor feedback only if telemetry is deliberately introduced with privacy safeguards; otherwise use voluntary feedback. | Measures value without assuming or silently collecting usage data. |

## 13. Top 10 Immediate Recommendations

1. **Make approval explicit and fail closed** for every API payload. A missing `approved` value must never mean “approve.”
2. **Preserve lifecycle regression tests** for the re-evaluation and atomic approval-claim fixes already present.
3. **Define trusted identity and session scope** for gateway callers; do not let an untrusted request body silently define the identity behind budgets and taint.
4. **Specify taint and budget lifetime** across restart, failure, external execution, and bounded-state eviction.
5. **Fix dry-run session propagation** so its `session_id` and taint context are the ones being simulated.
6. **Repair canary replay fidelity** before using it to approve or block policy releases.
7. **Make external outcome recording atomic and truthful by contract**; distinguish caller attestation from independently verified execution.
8. **Bind stored action context to audit integrity** and report when history cannot be faithfully replayed.
9. **Align README, product status, lifecycle docs, and `PLAN.md`**; separate supported, experimental, and planned behavior.
10. **Keep the product local-first and narrow** until real user feedback justifies more connectors, desktop packaging, or remote/team features.

## 14. Long-Term Vision (3–5 Years)

If Actentra proves useful to Python and MCP developers, it could mature into a compact, trusted local control plane for agent actions: one policy contract, several dependable integrations, clear human approval, and audit records whose limits and provenance are understandable. The operator application should remain a thin interface to the same SDK/services, while automation users retain a stable CLI and API.

Potential growth after evidence exists:

- Versioned policy and executor contracts for third-party integrations.
- Signed or off-host audit checkpoints for users who need stronger evidence than a local hash chain.
- Team workflows with authenticated principals and explicit approval roles.
- Additional integrations driven by actual repeated user requests.
- Optional desktop packaging if it materially improves setup or day-to-day use.

These are conditional possibilities, not current commitments. A hosted service or enterprise control plane would be a different product with substantially different identity, tenancy, operations, privacy, and security requirements.

## 15. Final Strategic Verdict

Actentra is worth developing further because its core problem—reliably authorizing consequential agent tool calls and recording what happened—is meaningful, and the repository already contains more than a conceptual prototype. The strongest strategy is to consolidate and prove what exists: eliminate permissive edge cases, define trust/session semantics, make canary and audit claims accurate, and deliver a clear local operator workflow. Do not pursue feature breadth as a substitute for these guarantees.

**Recommended owner strategy:** Treat authorization correctness and evidence as the product; keep the architecture modular but simple; ship a narrow local-first alpha only when the supported workflows have end-to-end proof; then let user evidence determine whether to invest in more connectors, packaging, or team capabilities.
