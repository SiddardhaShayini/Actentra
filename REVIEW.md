# Actentra: Project Discovery & Assessment

**Scope:** Static inspection of the repository’s source, tests, configuration, and documentation. No project commands, tests, builds, or applications were run; no files were changed. Conclusions about behavior are based on the code as inspected, not runtime verification.

## 1. Project overview

Actentra is a Python project intended to put a **deterministic authorization layer between AI agents and actions that affect external systems**. An agent proposes an action—such as reading a file, querying a database, or calling an HTTP endpoint—and Actentra evaluates it against policy, may require human approval, and records an audit receipt.

In non-technical terms, Actentra aims to be a **security checkpoint for an AI assistant**: the assistant can suggest an action, but a separate system decides whether it may proceed and records what happened.

**Analogy:** It is like a security desk that checks a visitor’s requested destination and access rules, asks a supervisor about uncertain requests, and keeps a log. The analogy has limits: Actentra only controls actions that are actually routed through it, and the repository does not establish OS-level isolation.

The product’s motivation is to reduce risk from agent mistakes, prompt manipulation, excessive permissions, runaway activity, and poor auditability. The project’s stated vision and threat framing are in `PLAN.md` and `docs/threat-model.md`.

## 2. Problem and solution

Without an action boundary, teams typically rely on a combination of application-specific checks, system credentials, human review, and downstream audit logs. Those mechanisms can be inconsistent across agent frameworks and may not record the exact action that was authorized.

Actentra’s proposed value is to centralize several controls:

- Canonicalize tool calls and evaluate them against a deny-by-default policy.
- Assign rule-based risk tags and apply rate or cumulative budgets.
- Require approval for actions matched to `ASK` rules.
- Restrict execution through scoped connectors.
- Record decisions and outcomes in a hash-chained local receipt store.

The problem is significant for agents that can touch consequential systems—particularly files, databases, or external services. Whether a separate project is justified depends on whether these controls are substantially easier to adopt and operate than application-specific authorization. The repository alone cannot show market demand or whether target users prefer this approach.

## 3. Target audience

The clearest initial audience is **developers and technical operators building agents that invoke tools**, especially Python users and teams experimenting with MCP. The project offers a Python SDK, CLI, framework adapters, MCP stdio proxy, and local HTTP console in `sdk/python/actentra/`, `cli/actentra_cli/`, and `gateway/actentra_gateway/`.

Users need to understand tool permissions, policy configuration, and at least some integration code. The repository does not yet support the conclusion that this is a turnkey product for ordinary users or a production-ready enterprise control plane. Business adoption, customer traction, and the operational support model **cannot be determined from the available source code**.

## 4. Architecture and technology

The project uses a layered Python architecture:

- **Core kernel:** envelopes and canonical hashes, resource canonicalization, risk tagging, policy evaluation, budgets, warrants, and receipts in `core/actentra_core/`.
- **SDK and adapters:** the `Boundary` mediates in-process Python calls; function-calling and LangChain adapters translate framework calls into Actentra actions in `sdk/python/actentra/`.
- **Executors:** filesystem, SQLite, and HTTP operations are implemented in `executors/actentra_executors/`.
- **Gateway and application services:** the HTTP service exposes API endpoints and a browser console; `AppServices` connects policy evaluation, approval state, executors, audit, and simulation in `gateway/actentra_gateway/`.
- **CLI:** Typer commands provide policy checks, dry-run, replay, reports, gateway operations, checkpoints, and warrants in `cli/actentra_cli/main.py`.
- **Contracts and configuration:** JSON Schemas, YAML policies, and example corpora are in `spec/`, `policies/`, and `corpus/`.

The normal intended data flow is: adapter receives a call → build and canonicalize an envelope → evaluate policy and risk → deny, ask, or permit → optionally dispatch to a scoped executor → record an outcome. SQLite stores receipts and approvals; YAML defines policy. The project depends on Python 3.12+, PyYAML, `cryptography`, and Typer, as declared in `pyproject.toml`.

## 5. Features and implementation status

### Implemented building blocks

- **Policy engine:** YAML rules, deny-by-default behavior, verdict precedence, linting, shadow mode, and rate limits in `policy.py`.
- **Action envelopes and canonicalization:** action metadata and hashing, Unicode normalization, Windows path checks, and resource matching in `envelope.py` and `canonicalize.py`.
- **Receipts and approvals:** SQLite WAL receipts, hash-chain verification, outcome recovery, and persisted approval records in `receipts.py`.
- **Scoped connectors:** filesystem operations, parameterized SQLite queries, and bounded HTTP responses in `fs.py`, `sqlite.py`, and `http.py`.
- **Operational tools:** CLI, local HTTP gateway, operator console, dry-run, canary, audit report, and MCP proxy across `cli/actentra_cli/main.py`, `http_service.py`, and `mcp_proxy.py`.
- **Tests and CI:** unit, replay, property, chaos, golden, and performance test areas are present under `tests/`, with a Windows/Python 3.12 CI workflow at `ci.yml`.

### Important limitations and incomplete integration

Having a feature’s module does not necessarily mean it is enforced throughout every execution path:

- **Gateway behavior needs careful qualification.** The HTTP application services can dispatch registered executors, but the approved-crossing continuation re-evaluates an action and does not check whether that decision permits execution before dispatch. The flow should not be assumed safe merely because approval persistence and execution dispatch exist. See `services.py`.
- **Warrants are not visibly part of the `Boundary` authorization path.** The project has signed capability-token utilities, but code presence is not evidence that every relevant crossing enforces them. See `warrants.py` and `boundary.py`.
- **Taint and cumulative budgets are not consistent across the SDK and gateway paths.** Gateway-provided session/provenance values are caller-controlled; the service does not visibly inherit session taint or update cumulative budget usage on successful dispatch. Compare `services.py` with `boundary.py`.
- **The secrets broker exists, but an end-to-end, broker-backed credential-injection workflow is not established by the code inspected.** In particular, HTTP constraints can carry secret-header values directly in `http.py`.
- **The project’s roadmap and current implementation descriptions are out of sync.** `PLAN.md` and `PROJECT_MEMORY.md` still describe Phase 0, while `README.md` describes a broad set of implemented and unified features.

These are reasons to verify guarantees per integration, not to assume every feature is absent.

## 6. Real-world usage

These are plausible uses of the current building blocks, not claims of existing deployments:

1. **Workspace file agent:** route file reads and writes through the filesystem executor, allow only a specific workspace, and record decisions and outcomes.
2. **Database assistant:** expose a constrained SQLite database and use policy to limit which queries and operations are allowed.
3. **MCP tool mediation:** place the stdio proxy between an MCP client and server to mediate `tools/call` requests and detect changed tool definitions.
4. **Outbound HTTP access:** allow a narrow set of HTTP operations and hosts, with request and response size limits.
5. **Local operator review:** run the gateway and console to inspect pending approvals, policy information, and receipts.

A typical developer workflow would be to define a policy, connect an agent via the SDK or MCP proxy, test proposed actions with dry-run or replay, enable mediation, and inspect receipts. Deployment options visible in the repository are an in-process Python library, an MCP stdio wrapper, or a local HTTP gateway. How to operate these safely in a production environment **cannot be determined from static inspection alone**.

## 7. Business and practical value

Actentra could save engineering effort when a team wants similar policy, approvals, and audit concepts across multiple agent tools. A local-first design may also suit teams that do not want agent action records sent to a hosted control plane.

The practical value is conditional: users must route relevant actions through Actentra and maintain accurate policies and connector configuration. It does not replace operating-system permissions, cloud IAM, or isolation from a compromised host; the repository states these limits in `docs/guarantees-and-limits.md`.

Commercial potential exists in the broad category of agent security and operations, but adoption, willingness to pay, support requirements, and differentiation are not evidenced by the repository. Those points **cannot be determined from the available source code**.

## 8. Strengths, weaknesses, and risks

### Strongest aspects

- A clear product idea: separate deterministic authorization from model-generated proposals.
- Meaningful architecture boundaries between core, integrations, and executors.
- Strong defaults in several parts of the design, including deny-by-default policies and durable decision receipts.
- A useful local developer toolset: CLI, SDK, MCP integration, dry-run, replay, and audit reporting.
- Explicit threat-model and guarantee-limit documentation.

### Main weaknesses and risks

- **Execution correctness and authorization are the main concern.** Approval continuations and alternate gateway paths need consistent checks; otherwise documented guarantees may not hold across integrations.
- **The HTTP executor checks destinations before requests but uses `urlopen`, which follows redirects.** Redirect targets are not visibly revalidated in `http.py`, creating an SSRF risk.
- **Remote gateway binding is explicitly gated, but the code does not require authentication whenever remote binding is enabled.** Authentication is optional in `http_service.py`; transport is plain HTTP.
- **Dynamic approval data is inserted into browser `innerHTML` without escaping** in `console.html`, creating stored script-injection risk if untrusted crossing data reaches the console.
- **Policy-relevant context and action hashes are not the same thing.** The action hash includes the action, session, and agent identity but not provenance; approval context and later execution should therefore be scrutinized for trust-context changes in `envelope.py` and `services.py`.
- **Some resource and audit operations are expensive at scale.** Full receipt verification and exports load records rather than streaming them, while the gateway accepts a receipt query limit without a visible maximum in `receipts.py` and `http_service.py`.
- **Testing evidence is uneven.** The suite has broad categories, but a receipt-search assertion in `test_app_services.py` ends with `or True`, so it cannot establish the expected search behavior. The CI workflow is a single Windows/Python 3.12 fast-check job in `ci.yml`.
- **Canonical JSON wording should be verified.** The console labels its hash format RFC 8785 in `console.html`, while the implementation uses Python’s sorted-key JSON serialization in `canonicalize.py`. Interoperability with other language implementations should not be assumed without matching test vectors.

The project’s strongest adoption risk is not lack of features; it is whether users can trust and understand the same lifecycle across all integrations.

## 9. Competition and alternatives

The repository’s `PLAN.md` itself recognizes adjacent work, including AARM and research systems such as AgentBound, ClawLess, and AgentGuardian. The repository does not provide enough sourced comparison to establish how those projects currently compare or whether Actentra is unique.

Some neighboring tools solve related but different problems:

- [NVIDIA NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) describes itself as a toolkit for programmable guardrails in LLM-based conversational systems.
- [Guardrails AI](https://github.com/guardrails-ai/guardrails) focuses on adding guardrails to LLM applications.
- [Microsoft Semantic Kernel](https://github.com/microsoft/semantic-kernel) is an LLM application/agent integration SDK, rather than a direct equivalent to a deterministic action-authorization boundary.

These examples should not be treated as feature-for-feature competitors. Other alternatives include application-specific authorization, standard IAM, and MCP-specific mediation; how they compare for a particular deployment depends on requirements.

Potential Actentra differentiators are local operation, Python integration, Windows-aware filesystem handling, deterministic policy evaluation, and local receipts. The repository contains design intent and implementation for these features, but **does not provide independent benchmarks, comparative security evaluations, or adoption data** to establish superiority.

## 10. Improvement opportunities

Priorities are based on likely impact, not feature count.

| Priority | What to improve | Why it matters | Recommended approach |
|---|---|---|---|
| **Critical** | Approved execution and policy re-checks in `services.py` | A denied or held decision must never dispatch an executor; approval must not permit duplicate execution. | Make the continuation enforce an execution-permitting decision and consume a still-valid approval atomically before dispatch. |
| **High** | Align taint, budgets, and identity across gateway and SDK paths | Caller-controlled sessions/provenance and missing budget accounting weaken policy behavior. | Define trusted session identity, propagate taint consistently, and record usage for every supported execution path. |
| **High** | Harden HTTP SSRF, remote gateway access, and console rendering | Redirects, optional remote authentication, and unescaped HTML are concrete security risks. | Revalidate redirects/destinations; require a protected remote mode; render dynamic content as text and add appropriate browser protections. |
| **High** | Define and test end-to-end security claims | Modules alone do not prove complete enforcement; warrants and secrets need clear integration status. | Create lifecycle tests per supported integration and label features as supported, experimental, or planned. |
| **Medium** | Bound gateway inputs and audit costs | Unbounded limits, full-log verification, and whole-log exports can cause performance problems. | Cap request/query sizes, paginate or stream log operations, and separate routine health checks from full verification. |
| **Medium** | Improve test strength and platform evidence | Vacuous assertions and limited CI weaken confidence in reported behavior. | Replace ineffective assertions; add tests for approvals, budgets, taint, redirects, and gateway concurrency; expand CI when platform support is claimed. |
| **Medium** | Reconcile docs and implementation status | Users need to know what is actually supported and what remains aspirational. | Keep one authoritative status/roadmap and ensure README, architecture, threat model, and quickstart agree. |
| **Low** | Broaden enterprise features or add more connectors | More capabilities increase maintenance and security surface before the current flow is settled. | Defer until user evidence and stable connector contracts justify expansion. |

## 11. Ratings and final evaluation

| Evaluation | Score | Justification |
|---|---:|---|
| Overall project quality | **6/10** | Strong concept and substantial engineering foundations, offset by integration gaps and conflicting project status. |
| Practical real-world usefulness | **6/10** | Useful for developers who can route actions through it; production confidence is not yet established. |
| Problem significance | **8/10** | Agent actions can cause real damage or data exposure, making external authorization and evidence valuable. |
| Technical architecture | **7/10** | Clear module boundaries and sensible local technologies; cross-path consistency and lifecycle semantics need work. |
| Feature completeness | **7/10** | Broad feature set, but some capabilities are primitives and not uniformly integrated. |
| Innovation / uniqueness | **6/10** | The combination is worthwhile, but adjacent guardrail and runtime-security efforts exist; uniqueness is unproven. |
| Business potential | **6/10** | A plausible niche product, but market demand, differentiation, and willingness to pay are unknown. |
| Production readiness | **3/10** | Static review surfaced important authorization, SSRF, gateway-authentication, and UI-security concerns; no runtime validation was performed. |
| Long-term potential | **8/10** | Could become a useful developer-and-operator boundary if the core lifecycle is made dependable and easy to adopt. |

- **Overall Project Value:** Genuinely valuable as a focused engineering direction: centralized authorization and audit for agent actions address real risks.
- **Importance:** More than a technical experiment in principle, but the current repository is still an early product implementation, not evidence of an established solution.
- **Real-World Adoption:** Developers and small teams may trial it; broader organizational adoption would require stronger integration evidence, security review, operational documentation, and demonstrated usability.
- **Biggest Opportunity:** Become a trusted, lightweight local action-authorization and audit layer that works consistently across Python and MCP-based agents.
- **Biggest Concern:** Whether all supported paths enforce the same authorization and execution guarantees. Gateway execution and trust-context handling deserve priority.
- **Final Verdict:** Worth developing further, but the next phase should prioritize correctness, security, and validated workflows over adding features.

## 12. Executive summary

1. Actentra is a Python-based policy and audit boundary for actions proposed by AI agents. It includes a policy kernel, SDK and adapters, scoped executors, CLI, MCP proxy, and local operator console. Its goal is to authorize and record tool actions independently of model judgment. The repository shows substantial implementation, but not production validation.
2. It is best suited to Python developers and technical teams building agents that use files, databases, HTTP tools, or MCP servers.
3. Someone might use it to centralize action policy, approval, and receipts instead of building those controls separately for every agent integration.
4. Its most valuable real-world application is mediating high-impact agent tool calls with clear policy decisions and durable audit history.
5. Its biggest limitation is inconsistent enforcement and trust handling across execution paths, alongside security concerns that need resolution.
6. **Honest overall rating: 6/10.**
7. **Final verdict:** Actentra addresses an important problem and is worth advancing, but its security guarantees need to be made consistent and independently validated before production reliance.