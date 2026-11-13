<p align="center">
  <img src="assets/actentra-logo-dark.svg" alt="Actentra" width="260" />
</p>

# Actentra V2 — Product and Architecture Roadmap

**Assessment date:** 2026-11-13  
**Decision:** A focused V2 is worthwhile. The highest-value direction is a unified, local-first operator application built around the existing deterministic kernel—not a rewrite of the kernel, a cloud control plane, or a full agent builder.

> **Assessment method:** This roadmap is based on static inspection of the repository's code and documentation only. No commands, applications, tests, builds, or installations were run for this assessment. Existing test results cited elsewhere in the repository were not independently revalidated here.

## 1. Current project assessment

Actentra is a local-first authorization and audit boundary for AI-agent tool calls. The central value proposition is clear: an agent proposes an action, a deterministic policy engine makes the authorization decision, constrained adapters or executors mediate supported work, and the system records a verifiable history.

The codebase already has meaningful breadth:

- **Core:** canonical envelopes and hashes, Windows-path/resource normalization, deterministic risk tags, deny-by-default YAML policies, rate and cumulative budgets, dry-run, policy linting, and a policy canary.
- **Evidence and cryptographic primitives:** SQLite WAL receipts with a hash chain, verification/export, signed checkpoints, and capability warrants.
- **Integrations:** an in-process Python `Boundary`, function-calling and LangChain adapters, an MCP stdio proxy, and a local HTTP gateway.
- **Executors:** scoped filesystem, SQLite, and HTTP operations.
- **Operator tooling:** a Typer CLI, a small embedded approval console, and standalone HTML audit reports.
- **Quality foundation:** JSON Schemas, unit/golden/property/chaos/replay/performance test directories, incident and benign corpora, strict type/lint configuration, and Windows CI.

The architecture is sensibly layered for a young project: the policy and receipt kernel is separate from adapters and executors, and the CLI, SDK, gateway, and schemas provide several ways to use it. Python, SQLite, and a dependency-light local service are consistent with the stated lightweight Windows-first goal.

**Maturity judgment:** this is a feature-rich alpha/prototype, not yet a production-ready enforcement product. The core concept and many building blocks are implemented, but the repository's own `PROJECT_MEMORY.md` records development through phases later than the Phase 0 status still shown in `PLAN.md`. Some roadmap descriptions remain aspirational or out of sync with what the runtime actually wires together. The next step should be integration, operational clarity, and validation—not adding a large number of new features.

## 2. Key problems and limitations

### Critical: the user-facing execution lifecycle is not yet unified

The SDK can evaluate, approve, execute a supplied callable, and record its outcome. The HTTP gateway's `/v1/crossings` path instead builds and evaluates an envelope and records a decision; it does not dispatch that action to one of the scoped executors or record an execution outcome. The approval endpoint grants a hash-bound approval to the in-memory `Boundary`, but a caller still needs a well-defined subsequent execution path. The current web console is therefore an approval/inspection surface, not a complete application for safely configuring and operating all major capabilities.

**Change:** define a single lifecycle contract for propose → evaluate → ask/approve → execute the same action → record outcome, and make each integration's role explicit.  
**Why/value:** prevents users from assuming an approval click itself performed or completed an action; makes the product coherent and auditable.  
**How:** keep execution behind a registered integration/executor, persist a pending action reference, and have approval authorize only that exact action for a bounded, one-time continuation. Never ask the UI to reconstruct action parameters from display text.

### Critical: local gateway operational boundaries need to be explicit

The HTTP service is a `ThreadingHTTPServer`; several API routes mutate control state, while the HTTP response helper permits wildcard CORS. The CLI defaults to loopback, which is an important safe default, but configurable host binding and browser-origin behavior need a product-level security contract before the console becomes a general control plane.

**Change:** establish a supported local-only operating mode and a separately designed remote mode, rather than treating a bind-address change as sufficient remote support.  
**Why/value:** approval and kill-switch endpoints are privileged controls; accidental network exposure or browser-origin confusion can undermine the local trust boundary.  
**How:** keep loopback as the default; restrict allowed origins; add CSRF-resistant browser request handling and local operator authentication/session protection as appropriate; require explicit, documented authentication and transport protection for any future remote binding. Make unsafe configurations visible and fail closed.

### High: pending decisions and runtime state are mostly process-local

Pending approvals live in an in-memory dictionary. Rate-limit and cumulative-budget state also live in process memory, and bounded state eviction can discard old session state. A restart can therefore lose pending work or reset enforcement context. `ThreadingHTTPServer` also means shared mutable state and receipt access need a documented concurrency model.

**Change:** specify which state must survive restart and make enforcement state safe under concurrent requests.  
**Why/value:** avoids ambiguous approval and budget behavior after restarts, while keeping state bounded and predictable.  
**How:** persist pending approval metadata and expiry/consumption status; serialize or transactionally coordinate policy state changes; define whether budgets are per process, per durable session, or intentionally reset. Add bounded queues, explicit overload behavior, and recovery rules before enabling longer-lived operation.

### High: important capabilities are primitives rather than end-to-end product workflows

Warrants can be issued and checked, but the SDK boundary does not appear to enforce them as part of its request lifecycle. The secret broker is available to the SDK, but connector-level secret retrieval and injection are not yet a complete, user-configurable workflow; the HTTP executor accepts secret header values from decision constraints. Policy reload, key lifecycle, warrant-use persistence, and approval administration also lack an integrated operator workflow.

**Change:** either wire these capabilities into supported end-to-end flows or label them clearly as experimental/low-level APIs.  
**Why/value:** separates demonstrable protection from code that is present but not yet part of the enforced product path.  
**How:** define a versioned executor and credential-reference contract; keep secret values out of policies, envelopes, and UI/API output; verify warrant scope at the authorization boundary; persist use limits if they are intended to survive restart. Do not market a primitive as an active control until an integration test exercises the complete path.

### High: audit and replay need scale, privacy, and integrity boundaries

Receipt verification and append-only hash chaining are useful local tamper-evidence mechanisms, but a local chain alone cannot prove that the entire database was not deleted or replaced. Receipt iteration, reports, and canary replay load records into memory; the target plan discusses rotation and compression, but those are not evident in the current receipt API. Full envelopes are stored separately from the receipt chain, and their persistence failure is suppressed, so historical replay may not have the same coverage as the original decision inputs.

**Change:** make audit retention, privacy, paging, replay fidelity, and anchoring explicit parts of the design.  
**Why/value:** keeps audit useful for real installations without unbounded memory or false claims of tamper-proofing.  
**How:** persist the exact policy-relevant request context needed for replay with an explicit integrity relationship; report when replay data is missing; provide bounded queries/export and a retention strategy; document external checkpoint anchoring as a separate protection. Add configurable redaction and local data-retention controls.

### Medium: policy and integration setup still require repository knowledge

Users currently need to edit YAML, understand tool/resource naming, select integration commands, and use CLI commands to simulate or inspect policy. The starter policy is useful but tied to a sample workspace convention. Adapter resource/verb inference is necessarily heuristic; custom tools still need deliberate mapping.

**Change:** make setup and policy validation guided, explainable, and previewable without hiding the underlying policy.  
**Why/value:** improves first-use success and reduces dangerously broad rules or confusing false denials.  
**How:** provide scoped templates, an integration setup checklist, policy lint output in plain language, and dry-run/canary previews that show the matched rule and rationale. Continue to expose and export the underlying YAML so the UI is not a proprietary policy format.

### Medium: quality evidence is stronger for the kernel than for the product

The repository has broad test categories and corpus-based checks, but the checked-in CI workflow is a single Windows/Python 3.12 fast-check job. The resource test measures the policy engine in the pytest process rather than an actual idle gateway lifecycle. The curated incident corpus has useful case labels, but its entries do not themselves provide source URLs, and it is not evidence of general attack prevention.

**Change:** add measured product-level acceptance criteria and broaden reproducible evidence before making stronger deployment claims.  
**Why/value:** helps users distinguish tested behavior from intended guarantees.  
**How:** add end-to-end lifecycle tests for each supported integration; test restart/recovery and bounded concurrent use; measure the gateway's actual idle and peak footprint; add cross-platform checks only when those platforms are supported; attach provenance/source references to corpus cases and clearly label synthetic scenarios. Keep heavy testing opt-in locally or in CI to respect the lightweight-development constraint.

### Medium: documentation and product status have drifted

`PLAN.md` describes Phase 0 and assigns MCP, the web UI, secrets, taint, and warrants to future phases, while the implementation and `PROJECT_MEMORY.md` describe many of those features as already built. The README presents a broad feature set without a concise distinction between available, experimental, and planned behavior.

**Change:** reconcile status, supported workflows, guarantees, and roadmap in one maintained product-status source.  
**Why/value:** reduces onboarding confusion and prevents implementation details from being mistaken for validated production guarantees.  
**How:** after V2 scope is agreed, update the existing roadmap and feature documentation as part of implementation; label each capability as supported, experimental, or planned and state platform limitations. This V2 plan does not modify those existing documents.

## 3. Proposed improvements and enhancements

1. **Finish and document the action lifecycle — Critical.** Specify the interaction between SDK, MCP, HTTP, approval, executors, and receipts; define exact behavior for approval expiry, duplicate submissions, timeouts, retries, and unknown outcomes. Implement the smallest complete supported path first.
2. **Harden local operations and recovery — Critical.** Keep the app loopback-only by default; establish browser-origin and privileged-route protections; persist pending approvals; define concurrency, state recovery, and overload behavior.
3. **Build one operator application over the existing capabilities — High.** Start, inspect status, review approvals, inspect policy decisions, run dry-run/canary, and explore receipts from one local interface. The UI should call the same application services as the CLI, not implement a parallel policy engine.
4. **Create an explicit integration and executor contract — High.** Define how an adapter describes a tool, how resource/verb mapping is reviewed, how an executor receives only an authorized canonical action, and what outcome information is recorded. Keep the first-party connectors narrow; do not make arbitrary third-party plugins trusted by default.
5. **Improve audit usability and boundedness — High.** Add paged receipt queries and report filters; clarify chain limitations; define retention/rotation and local privacy behavior; improve replay fidelity and report incomplete historical data.
6. **Make claims testable — High.** Add product-level tests and metrics for the supported workflows, startup/idle resource use, concurrency, restart behavior, and user setup. Treat corpus pass rates as a measure of defined scenarios, not a general security score.
7. **Simplify the release/onboarding story — Medium.** Provide a documented first-run workflow, a safe default policy, a clear “local only” posture, and a small set of primary paths (SDK, MCP, local console). Defer installers and background startup until the core workflow is stable.
8. **Defer enterprise architecture — Low for V2.** Do not introduce a cloud control plane, multi-tenancy, SSO, PostgreSQL, or a Rust rewrite until real use and measured constraints require them.

## 4. New feature ideas and their value

| Priority | Feature | Purpose and value | Practical implementation |
| --- | --- | --- | --- |
| High | Local setup and integration wizard | Helps a new user choose an integration, create a scoped policy, and verify a first safe/blocked action without hunting through files. | A short guided web flow that generates ordinary YAML, previews it, and offers CLI/SDK/MCP setup instructions. |
| High | Approval inbox with action detail | Gives an operator enough context to approve or deny intentionally and see expiry/status. | Display canonical action fields, sanitized parameter summaries, matched rule, reason, risks, provenance, exact hash, and whether approval will authorize a later execution. Do not display secrets. |
| High | Policy simulator and canary viewer | Makes policy changes safer and explains denials before enforcement. | Reuse existing dry-run, lint, and canary functions; show before/after verdicts and permission relaxations; preserve a reviewable YAML file. |
| High | Receipt explorer | Makes the existing audit capabilities discoverable and helps investigate failures. | Search/filter by session, tool, verdict, rule, risk, and time; paginate results; link decision/outcome; clearly surface chain verification and missing action context. |
| Medium | Integration health and lifecycle status | Makes the currently separate runtime paths understandable. | Show local gateway health, selected policy/version, receipt-store status, active/pending work, and configured integrations. No automatic daemon startup. |
| Medium | Exportable policy and audit bundles | Simplifies review, support, and offline evidence sharing. | Export policy plus a bounded receipt selection, integrity result, version metadata, and redaction choices; keep exports offline and self-contained. |
| Low | Additional connectors and framework adapters | Extends reach once the interface is stable. | Add only in response to a clear user need, with scoped operations, adapter tests, executor tests, and documented limits. |

## 5. Unified application concept and feasibility

### Recommendation

**Yes—technically feasible and likely to improve the project.** Actentra already has a local HTTP service, a browser console, policy evaluation, approval primitives, receipt reporting, dry-run/canary functions, and CLI entry points. Those are a strong foundation for a lightweight control surface.

The feasible V2 is a **single-user, local-first operator application** that brings setup and operation together while preserving the Python SDK and CLI for developers. It should not try to turn Actentra into a general workflow builder, agent runtime, or hosted security platform.

### What “unified” should mean

- One place to configure and understand Actentra's local runtime.
- A consistent view of policies, decisions, pending approvals, receipts, and integration status.
- Shared application services underneath the web UI, CLI, SDK, and MCP adapter.
- No requirement that users browse the repository to perform routine setup or audit.
- Existing programmatic interfaces remain available; the UI is an additional interface, not a replacement.

### Feasibility boundaries

- **High feasibility:** serving a static, responsive local UI from the existing Python gateway and calling well-defined local API routes.
- **Moderate effort:** integrating policy workflows, persisted approvals, receipt browsing, and setup instructions with reliable state and clear authorization semantics.
- **Not a V2 prerequisite:** native desktop packaging, remote team administration, cloud synchronization, multi-user access, or a distributed execution service.
- **Not currently established:** one integrated runtime that executes all HTTP-submitted crossings through the built-in executors. The lifecycle/API contract must be settled first.

### Would it genuinely improve the product?

Yes, if usability is a current adoption barrier and the interface makes policy and action status easier to understand. It reduces the need to memorize CLI subcommands and manually inspect SQLite logs or YAML. It is not automatically safer merely because it has a UI: an attractive approval button can increase approval fatigue. The UI must explain exactly what is being authorized, preserve least privilege, and avoid giving users the impression that an unexecuted decision has completed.

## 6. Proposed application architecture

Keep the deterministic kernel as the stable foundation and add a small application/service layer around it:

```text
Python SDK / MCP adapter / CLI / Local web UI
                     |
           Versioned application API
     (setup, policy, approvals, audit, health)
                     |
          Actentra application services
   (lifecycle orchestration, state, validation)
                     |
       Existing deterministic core/kernel
 (canonicalization, risk, policy, budgets, receipts)
                     |
        Explicitly scoped executors/connectors
        (filesystem, SQLite, HTTP; as enabled)
                     |
             Local SQLite + policy files
```

### Architectural rules

1. **One policy authority:** the existing deterministic core is the only decision engine. UI-side JavaScript never decides whether an action is allowed.
2. **One lifecycle contract:** every supported path records a decision before execution, executes only the authorized action, and records the outcome or an explicit unknown.
3. **Separate presentation from execution:** the web UI can inspect and request approval; it does not gain arbitrary filesystem, shell, or network authority.
4. **Local-first by default:** bind to loopback, persist to user-selected local paths, and require explicit opt-in for anything beyond the current process/user boundary.
5. **Adapters remain thin:** framework-specific parsing and mapping belongs at integration edges; the kernel receives a canonical envelope.
6. **Keep the core replaceable but do not rewrite it prematurely:** preserve the language-neutral specs and measure bottlenecks before considering Rust/Go or a different storage engine.
7. **Keep deployment lightweight:** serve static assets from the Python app; avoid Electron, a second JavaScript server, mandatory containers, cloud services, and auto-start behavior in V2.
8. **Use bounded operations:** cap request sizes, result sizes, queues, pagination, timeouts, and retained in-memory session state; surface saturation explicitly as HOLD/429 rather than silently accepting unbounded work.

### State and API design

- Version the local API and define stable request/response shapes from the existing Envelope, Policy, Decision, and Receipt concepts.
- Treat pending approvals as durable, expiring references to the original action and decision; approval must not mutate the action or bypass a fresh authorization check.
- Define idempotency and duplicate-submission behavior for actions that may have side effects.
- Store policy-relevant replay context with explicit integrity/retention guarantees; distinguish missing replay context from “same as original.”
- Use bounded receipt query endpoints instead of returning the entire log for normal UI use.
- Return actionable errors for invalid policy, unavailable storage, expired approval, missing integration, or overloaded service; never return a success-shaped fallback.

## 7. Recommended UI/UX direction

### Navigation

Use a small left navigation or top-level tabs:

1. **Overview** — runtime status, active policy/version, recent decision counts, integrity state, and pending approvals.
2. **Approvals** — pending actions first, then resolved/expired history.
3. **Policies** — inspect current YAML, run validation/lint, compare a candidate, and export the file.
4. **Simulator** — submit a hypothetical tool/resource/verb/parameter summary and see verdict, risk tags, matched rule, and constraints without execution.
5. **Receipts** — filterable, paginated decision/outcome timeline with verification state and export.
6. **Integrations** — setup instructions and status for SDK, MCP proxy, and local API; show exactly what is and is not connected.
7. **Settings** — local data location, approval expiry, bind/security posture, and optional retention settings.

### Key interaction principles

- **Show safety state, not just activity:** make `enforce`, `shadow`, `frozen`, missing policy, and receipt-integrity status persistently visible.
- **Explain a verdict:** show the matched rule, its reason, relevant risk/provenance, and whether the result is simulated or real.
- **Make approval specific:** show the exact tool, verb, resource, parameter summary, action hash, policy version, and expiry. Require an explicit decision; default to deny on timeout or disconnection.
- **Distinguish decision from execution:** use separate statuses such as “awaiting approval,” “approved for execution,” “executed,” “failed,” and “outcome unknown.” Never label an approval as a completed action.
- **Keep the interface calm and compact:** responsive layout, keyboard access, clear focus states, high contrast, no charts or animation that obscure exceptional states.
- **Be privacy-conscious:** hide or redact sensitive parameter values by default; make any reveal deliberate and auditable.
- **Support progressive disclosure:** new users get a short, safe setup flow; advanced users can inspect raw YAML, canonical hashes, receipts, and integration details.
- **No cloud dependency:** bundle CSS/JavaScript locally and make the UI function offline.

## 8. Technical changes required

### Critical

- Define and document the end-to-end crossing and approval lifecycle for SDK, MCP, and HTTP, including exactly where execution occurs.
- Complete the HTTP approval continuation path or explicitly constrain HTTP to decision-only operation and rename/document it accordingly.
- Persist pending approvals and make them single-use, session/hash-bound, expiring, and recoverable after process restart.
- Set explicit local API protections: loopback default, restricted origins, safe browser request behavior, and a documented/authenticated remote mode only if later required.
- Establish concurrency control for policy, budget, approvals, and receipt operations; define behavior for overload, storage failure, and interrupted execution.

### High

- Introduce a small typed application-service layer used by the CLI and web UI, keeping transport and UI logic out of the core.
- Add paginated/filterable receipt queries and ensure UI/report/canary paths remain bounded for large logs.
- Make replay inputs complete and verifiable; expose incomplete data instead of silently treating it as a faithful replay.
- Integrate secret references and warrant checks into supported execution paths, or clearly mark those capabilities as low-level/experimental.
- Add user-visible policy editing/validation/simulation without creating a second policy format.
- Add lifecycle, restart, concurrency, and resource tests for the actual gateway and operator application.

### Medium

- Define a versioned connector registration contract and compatibility policy before inviting third-party plugins.
- Add storage retention/rotation and export controls; keep cryptographic checkpoints distinct from external anchoring.
- Add CI coverage for supported Python/platform combinations and a scheduled heavier test job, while keeping ordinary local checks fast.
- Review packaging and first-run configuration so documentation, package metadata, schemas, starter policies, and assets agree.

### Low / defer

- Native Windows desktop wrapper or installer.
- Remote operator access, multi-user roles, SSO, multi-tenancy, hosted control plane.
- Additional database backends, distributed execution, and a core-language rewrite.
- Optional ML/classifier signals; deterministic policy remains the sole authority to allow.

## 9. Potential challenges and risks

| Risk | Why it matters | Mitigation |
| --- | --- | --- |
| UI implies more integration than exists | Users may assume a displayed approval directly executes an action. | Settle the lifecycle contract first; expose accurate statuses and integration capability boundaries. |
| Approval fatigue | A polished inbox can make high-impact approvals routine. | Show action-specific context, risk, provenance, policy reason, and expiry; provide no blanket “approve all” path in V2. |
| Local web surface becomes a control-plane exposure | Browser/API routes can alter enforcement state. | Loopback by default, origin protections, explicit remote mode and authentication before any non-local use. |
| State grows or disappears unexpectedly | In-memory session state and unbounded log reads do not fit long-running usage. | Persist only necessary state, define eviction/reset behavior, add paging/retention, and measure bounded resource use. |
| More connectors expand the trusted computing base | Each parser and executor introduces new authority and failure modes. | Keep connector scopes narrow, require a test contract, and do not load arbitrary plugins in-process with ambient authority. |
| Claims overstate protection | Passing curated cases does not establish general prevention or host-level isolation. | Publish tested scope and residual limits; obtain independent review before production/1.0 claims. |
| V2 scope overloads a solo-maintained project | Too many features can delay a usable, dependable release. | Make the local operator workflow the only product expansion; defer enterprise and platform work. |
| Brand or package naming remains uncleared | Existing documentation states that Actentra is a working name. | Complete the existing clearance checklist before commercial launch or material brand investment. |

## 10. Priorities

- **Critical:** trustworthy action/approval lifecycle; local API security posture; persistent approvals and predictable recovery; honest supported-capability documentation.
- **High:** unified local operator UI; first-run setup and policy simulation; bounded receipt/audit workflows; end-to-end integration tests; explicit executor contract.
- **Medium:** connector extensibility; retention/rotation and replay improvements; broader CI and external beta evidence; packaging polish.
- **Low:** native desktop shell, remote/team control plane, enterprise identity, hosted service, more backends, multi-node execution, ML advisory features.

## 11. Suggested implementation phases

Phase lengths below are indicative for a small team or one maintainer; validate scope and capacity before committing dates.

### Phase 0 — Product contract and scope (1–2 weeks)

- Reconcile implementation status across `PLAN.md`, `PROJECT_MEMORY.md`, README, and docs.
- Decide and document whether HTTP crossings are decision-only or execute through registered connectors.
- Specify crossing states, approval semantics, restart behavior, and what “local-only” means.
- Identify the first intended user and the three most important workflows.

**Exit:** one lifecycle diagram and contract covers the supported SDK, MCP, and HTTP paths; all current features are labeled supported, experimental, or planned.

### Phase 1 — Close lifecycle and operational gaps (2–4 weeks)

- Implement the chosen approval continuation model and persist pending approval state.
- Harden local API/browser-origin behavior and make non-local binding explicitly unsupported or protected.
- Define concurrency, idempotency, timeout, retry, and unknown-outcome behavior.
- Add targeted end-to-end tests for allow, deny, ask/approve, expiration, restart, storage failure, and execution outcome.

**Exit:** every supported execution path has an unambiguous decision-to-outcome record trail; approval cannot change the approved action; restart and error cases are explicit and tested.

### Phase 2 — Unified local operator application (3–5 weeks)

- Add the overview, approvals, policy/simulator, receipt explorer, integration status, and settings views.
- Reuse existing core functions and introduce only the application services needed to avoid duplicated behavior.
- Add a safe first-run flow that generates inspectable YAML and verifies the local setup.
- Keep static assets local, no auto-start, no Electron, and no external network dependencies.

**Exit:** a new user can initialize a scoped policy, simulate an allowed and denied action, inspect a pending approval and its resolution, and verify/export a receipt without manually querying SQLite or searching source folders.

### Phase 3 — Reliability, audit, and limited beta (3–6 weeks)

- Add paginated receipt/report/canary paths, replay fidelity indicators, and retention guidance.
- Measure actual gateway startup/idle/peak resource use and bounded behavior on the target Windows laptop.
- Improve corpus provenance and publish reproducible scope/limits.
- Run a small user trial focused on setup time, approval comprehension, policy mistakes, and recovery.

**Exit:** meet agreed resource targets on actual hardware; no unbounded response paths in normal UI flows; usability feedback yields a prioritized fix list; security limitations are documented.

### Phase 4 — Stabilize supported integrations (after beta evidence)

- Prioritize fixes to the first integrations users actually adopt.
- Add platform support only with dedicated canonicalization/executor tests and CI evidence.
- Integrate warrants/secrets only where end-to-end testing demonstrates the expected control.
- Obtain independent review of the core and local control surface before production/1.0 positioning.

**Exit:** supported workflows, compatibility guarantees, security posture, and release process are reviewable and repeatable. Do not define success by feature count.

### Phase 5 — Long-term options (year 2+, conditional)

Consider team administration, remote policy management, SSO/RBAC, externally anchored audit, more storage backends, plugin isolation, and hosted control only after several real deployments establish demand. Any remote/control-plane direction requires a new threat model and trust-boundary design; it is not a natural consequence of the local UI.

## 12. Long-term vision

Actentra can become a dependable **authority and evidence layer for agent actions**: small enough to run locally, consistent across frameworks, and useful to both developers and operators. The durable differentiator should be transparent policy decisions, exact action binding, bounded execution, and verifiable records—not a large dashboard or an ever-growing list of connectors.

The long-term product can have two complementary faces:

- **Developer interface:** SDK, adapters, MCP proxy, CLI, and stable schemas for integrating actions into existing agents.
- **Operator interface:** a lightweight local console for policy, approvals, health, simulation, and audit.

If adoption later requires shared team policy, multi-operator approvals, or centralized evidence, evolve the service boundary deliberately with authentication, identity, authorization, isolation, and deployment operations designed from the beginning. Keep the local product valuable and usable without those services.

## 13. Recommendation

Proceed with V2 planning, but focus it on **completing and clarifying the product already present**. The unified application is feasible and likely worthwhile as a local web console served by the existing Python service, with the CLI and SDK retained. First close the action/approval lifecycle and operational boundaries; then add the UI as a thin presentation layer over shared services. Defer native desktop packaging, remote access, enterprise control-plane features, and broad connector expansion until user evidence justifies them.
