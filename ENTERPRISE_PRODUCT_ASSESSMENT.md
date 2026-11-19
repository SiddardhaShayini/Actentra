# Enterprise Product Assessment

## Target customer

The clearest near-term target is a **security-conscious team piloting autonomous Python/LLM workflows on a controlled Windows endpoint**, especially for filesystem, SQLite, or tightly allowlisted HTTP operations.

Likely buyers:

- platform engineering teams testing MCP or agent tool calls
- security teams requiring auditable execution decisions
- regulated teams needing a local control boundary and approval trail
- small software teams with a limited tool surface

No market demand or adoption numbers were assessed from repository evidence.

## Problem addressed

Actentra addresses three practical problems:

1. prevent tool calls outside explicit policy/approval
2. preserve evidence of proposals, decisions, approvals, execution, and outcomes
3. enforce local resource and credential scoping

The in-process SDK and MCP proxy are useful for reducing accidental dangerous actions and detecting tool/policy regressions.

## Current differentiation

Potential differentiation is the combination of:

- deterministic, zero-LLM policy decisions
- exact-action approval binding
- SQLite restart-safe lifecycle
- tamper-evident receipts
- MCP tool schema pinning
- local DPAPI secret broker
- typed evidence and postcondition models

This is differentiated as an engineering/reference architecture, but the repository does not demonstrate superior independent validation, production scale, or enterprise integrations.

## Competitive landscape

The repository does not include evidence for direct market comparison. Adjacent categories include:

- API gateways and service meshes
- enterprise secrets managers
- egress security proxies and SSRF controls
- MCP gateways and tool management
- agent frameworks with tool authorization
- PAM/IAM and workload identity systems
- SIEM/audit platforms
- AI governance and agent runtime platforms

Actentra may complement those products rather than replace IAM, network policy, secrets management, or SIEM.

## Deployment friction

Positive:

- Python package and CLI
- no GPU/container requirement
- local SQLite state
- embedded console
- starter policy

Negative:

- Python 3.12 requirement
- Windows-first secrets and local assumptions
- process-local configuration and state
- no enterprise installer or packaging
- no native TLS, identity, vault, HA, or Kubernetes support
- no straightforward policy distribution or tenant onboarding
- broad API surface for a pre-1.0 project

## Operational complexity

For a solo deployment, operations include:

- policy authoring/review
- approval handling
- database backup and archive
- checkpoint signing and key custody
- secret store configuration
- executor registration
- gateway authentication
- incident and recovery procedures

It may be simpler to deploy than a distributed platform, but it lacks automation for routine enterprise operations.

## Product limitations

- local-first architecture
- process-local identity and quotas
- SQLite not a distributed coordination database
- limited executors
- no general shell process executor abstraction
- HTTP executor lacks pinned DNS
- external outcomes are caller-reported
- postcondition semantics can still mark success before verification
- no general SaaS/API control plane
- no native OIDC/SAML
- no native secrets/KMS/HSM/vault integration
- no HA/disaster-recovery orchestration
- no signed release/SBOM evidence
- no independent security certification

## Adoption barriers

1. Enterprise identity and tenant isolation are absent.
2. Critical action evidence is not independently authenticated.
3. SQLite and bearer-token gateway do not meet control-plane HA expectations.
4. Documentation makes stronger status claims than runtime architecture supports.
5. Supply-chain and release security are unproven.
6. Installation/integration guidance is not yet vendor-operational.
7. Performance/scale evidence is limited.

## Commercial opportunity

A practical commercial path is to focus on **one team/one host agent-tool control**, with an offline or on-prem product and services. A possible paid model is:

- managed policy authoring
- approval/SIEM connectors
- enterprise identity
- durable state and HA
- independent audit reports
- support and certification

No repository evidence supports a claim of demand or willingness to pay. The project should avoid enterprise claims until P0/P1 controls and independent assurance exist.

## Buy/no-buy assessment

**No-buy for critical systems today.** Purchase or deployment should wait until the control plane is authenticated and production-validated.

**Pilot-only fit:** low-risk coding/test tools under an isolated account and tightly allowed resources.

**Future fit:** enterprise agent execution gateway if identity, distributed state, external evidence, and operational controls are delivered.
