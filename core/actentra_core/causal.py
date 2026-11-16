"""Causal trace and referential integrity for Actentra (Phase 3).

Provides typed causal links, DAG cycle detection, and causal trace reconstruction
linking proposals, policy decisions, approvals, execution outcomes, and state observations.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from actentra_core.receipts import ReceiptStore

_VALID_LINK_RELATIONS: frozenset[str] = frozenset(
    {"caused_by", "verifies", "derived_from", "triggers", "part_of"}
)
_VALID_ENTITY_TYPES: frozenset[str] = frozenset(
    {"crossing", "observation", "task", "receipt", "approval"}
)
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class CausalError(ValueError):
    """Raised when causal link construction or validation fails."""


class CycleDetectedError(CausalError):
    """Raised when adding a causal link would introduce a cyclic dependency."""


def generate_link_id() -> str:
    """Generate a Crockford Base32 identifier with 'lnk_' prefix."""
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bytes = os.urandom(10)
    value = (ts_ms << 80) | int.from_bytes(rand_bytes, "big")
    chars = ["0"] * 26
    for i in range(25, -1, -1):
        chars[i] = _CROCKFORD[value & 0x1F]
        value >>= 5
    return f"lnk_{''.join(chars)}"


def utc_iso(ts: float | None = None) -> str:
    """Format UTC timestamp in ISO-8601 format."""
    dt = datetime.fromtimestamp(ts, UTC) if ts is not None else datetime.now(UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CausalLink:
    """Explicit typed directional relationship connecting crossings, tasks, or observations."""

    link_id: str
    link_version: str
    source_id: str
    source_type: Literal["crossing", "observation", "task"]
    relation: Literal["caused_by", "verifies", "derived_from", "triggers", "part_of"]
    target_id: str
    target_type: Literal["crossing", "observation", "task"]
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert causal link to dictionary for API serialization."""
        return {
            "link_id": self.link_id,
            "link_version": self.link_version,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "relation": self.relation,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CausalLink:
        """Construct CausalLink from dictionary representation."""
        return cls(
            link_id=str(data["link_id"]),
            link_version=str(data.get("link_version", "1")),
            source_id=str(data["source_id"]),
            source_type=data["source_type"],
            relation=data["relation"],
            target_id=str(data["target_id"]),
            target_type=data["target_type"],
            created_at=str(data.get("created_at") or utc_iso()),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(frozen=True, slots=True)
class CausalTraceNode:
    """A node in the reconstructed causal DAG."""

    node_id: str
    entity_type: Literal["crossing", "observation", "task", "receipt", "approval"]
    role: Literal["proposal", "decision", "approval", "outcome", "observation", "task"]
    label: str
    timestamp: str
    status: str
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "entity_type": self.entity_type,
            "role": self.role,
            "label": self.label,
            "timestamp": self.timestamp,
            "status": self.status,
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class CausalTraceEdge:
    """A directed edge in the causal DAG."""

    source_id: str
    target_id: str
    relation: str
    edge_type: Literal["intrinsic", "explicit"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "edge_type": self.edge_type,
        }


@dataclass(frozen=True, slots=True)
class CausalTimelineEvent:
    """Ordered event in a reconstructed causal timeline."""

    step: int
    timestamp: str
    entity_id: str
    role: str
    summary: str
    authority: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "timestamp": self.timestamp,
            "entity_id": self.entity_id,
            "role": self.role,
            "summary": self.summary,
            "authority": self.authority,
        }


@dataclass(frozen=True, slots=True)
class CausalTrace:
    """Complete causal trace graph and ordered timeline."""

    root_id: str
    root_type: Literal["crossing", "observation", "task"]
    nodes: list[CausalTraceNode]
    edges: list[CausalTraceEdge]
    timeline: list[CausalTimelineEvent]
    dag_verified: bool
    missing_references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_id": self.root_id,
            "root_type": self.root_type,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "timeline": [t.to_dict() for t in self.timeline],
            "dag_verified": self.dag_verified,
            "missing_references": list(self.missing_references),
        }

    def render_ascii(self) -> str:
        """Render trace as human-readable ASCII timeline and DAG."""
        missing_desc = (
            ", ".join(self.missing_references) if self.missing_references else "None"
        )
        lines: list[str] = [
            f"=== Actentra Causal Trace [{self.root_type}: {self.root_id}] ===",
            f"DAG Verified: {self.dag_verified} (Acyclic)",
            f"Missing References: {missing_desc}",
            "",
            "--- Causal Timeline ---",
        ]
        for event in self.timeline:
            lines.append(
                f"  [{event.step:02d}] {event.timestamp} | {event.role.upper():<11} | "
                f"{event.summary} (Auth: {event.authority})"
            )

        lines.extend(["", "--- Causal DAG Edges ---"])
        if not self.edges:
            lines.append("  (No dependency edges)")
        else:
            for idx, edge in enumerate(self.edges):
                prefix = "└── " if idx == len(self.edges) - 1 else "├── "
                lines.append(
                    f"  {prefix}[{edge.source_id}] ──({edge.relation})──> [{edge.target_id}]"
                )
        return "\n".join(lines)


def detect_cycles(edges: list[CausalTraceEdge]) -> bool:
    """Return True if directed edges contain any cycles, False if acyclic DAG."""
    adj: dict[str, list[str]] = {}
    for edge in edges:
        adj.setdefault(edge.source_id, []).append(edge.target_id)

    visited: set[str] = set()
    rec_stack: set[str] = set()

    def _has_cycle(node: str) -> bool:
        visited.add(node)
        rec_stack.add(node)
        for neighbor in adj.get(node, []):
            if neighbor not in visited:
                if _has_cycle(neighbor):
                    return True
            elif neighbor in rec_stack:
                return True
        rec_stack.remove(node)
        return False

    all_nodes = set(adj.keys())
    return any(node not in visited and _has_cycle(node) for node in all_nodes)


def build_causal_trace(
    store: ReceiptStore,
    root_id: str,
    *,
    root_type: Literal["crossing", "observation", "task"] | None = None,
    max_depth: int = 10,
) -> CausalTrace:
    """Reconstruct the causal trace graph and timeline for a given entity."""
    # Infer root_type if not explicitly passed
    resolved_root_type: Literal["crossing", "observation", "task"]
    if root_type is not None:
        resolved_root_type = root_type
    elif root_id.startswith("obs_"):
        resolved_root_type = "observation"
    elif root_id.startswith("task_"):
        resolved_root_type = "task"
    else:
        resolved_root_type = "crossing"

    nodes: dict[str, CausalTraceNode] = {}
    edges: list[CausalTraceEdge] = []
    missing_refs: list[str] = []
    visited_crossings: set[str] = set()
    visited_observations: set[str] = set()

    def _expand_crossing(crossing_id: str, depth: int) -> None:
        if crossing_id in visited_crossings or depth > max_depth:
            return
        visited_crossings.add(crossing_id)

        # 1. Proposal
        envelope_data = store.get_envelope(crossing_id, verify_integrity=False)
        proposal_node_id = f"{crossing_id}:proposal"
        if envelope_data:
            action_info = envelope_data.get("action", {})
            tool = action_info.get("tool", "unknown")
            verb = action_info.get("verb", "unknown")
            resource = action_info.get("resource", "")
            agent_id = envelope_data.get("agent", {}).get("id", "caller")
            prop_ts = envelope_data.get("ts", utc_iso())
            nodes[proposal_node_id] = CausalTraceNode(
                node_id=proposal_node_id,
                entity_type="crossing",
                role="proposal",
                label=f"Proposal {tool}.{verb}",
                timestamp=prop_ts,
                status="proposed",
                summary=f"Caller ({agent_id}) proposed {tool}.{verb} on {resource}",
                metadata={"action": action_info, "agent_id": agent_id},
            )
        else:
            nodes[proposal_node_id] = CausalTraceNode(
                node_id=proposal_node_id,
                entity_type="crossing",
                role="proposal",
                label="Proposal",
                timestamp=utc_iso(),
                status="unknown",
                summary=f"Crossing proposal for {crossing_id}",
            )

        # 2. Decision
        decision_rec = store.get_decision_receipt(crossing_id)
        decision_node_id = f"{crossing_id}:decision"
        if decision_rec:
            verdict = decision_rec.verdict or "unknown"
            rule_id = decision_rec.rule_id or "default"
            nodes[decision_node_id] = CausalTraceNode(
                node_id=decision_node_id,
                entity_type="receipt",
                role="decision",
                label=f"Verdict: {verdict.upper()}",
                timestamp=decision_rec.ts,
                status=verdict,
                summary=f"Policy verdict {verdict.upper()} via rule '{rule_id}'",
                metadata={
                    "rule_id": rule_id,
                    "verdict": verdict,
                    "risk_tags": list(decision_rec.risk_tags),
                },
            )
            edges.append(
                CausalTraceEdge(
                    source_id=proposal_node_id,
                    target_id=decision_node_id,
                    relation="evaluates_to",
                    edge_type="intrinsic",
                )
            )
        else:
            missing_refs.append(f"{crossing_id}:decision")

        # 3. Approval (if any)
        approval = store.get_pending_approval(crossing_id)
        last_exec_source = decision_node_id
        if approval:
            approval_node_id = f"{crossing_id}:approval"
            resolved_at = approval.resolution_ts or approval.ts
            status_label = approval.status.upper()
            nodes[approval_node_id] = CausalTraceNode(
                node_id=approval_node_id,
                entity_type="approval",
                role="approval",
                label=f"Approval: {status_label}",
                timestamp=resolved_at,
                status=approval.status,
                summary=f"Operator approval {status_label}",
                metadata={"status": approval.status, "reason": approval.reason},
            )
            edges.append(
                CausalTraceEdge(
                    source_id=decision_node_id,
                    target_id=approval_node_id,
                    relation="requires_approval",
                    edge_type="intrinsic",
                )
            )
            last_exec_source = approval_node_id

        # 4. Outcome
        outcome_rec = store.get_outcome_receipt(crossing_id)
        outcome_node_id = f"{crossing_id}:outcome"
        if outcome_rec:
            status = outcome_rec.status or "unknown"
            reason = outcome_rec.reason or ""
            authority = "caller_reported" if "caller" in reason.lower() else "executor_observed"
            nodes[outcome_node_id] = CausalTraceNode(
                node_id=outcome_node_id,
                entity_type="receipt",
                role="outcome",
                label=f"Outcome: {status.upper()}",
                timestamp=outcome_rec.ts,
                status=status,
                summary=(
                    f"Execution outcome: {status.upper()}"
                    + (f" ({reason})" if reason else "")
                ),
                metadata={
                    "status": status,
                    "result_hash": outcome_rec.result_hash,
                    "authority": authority,
                },
            )
            edges.append(
                CausalTraceEdge(
                    source_id=last_exec_source,
                    target_id=outcome_node_id,
                    relation="executes_to",
                    edge_type="intrinsic",
                )
            )
            last_event_node = outcome_node_id
        else:
            last_event_node = last_exec_source

        # 5. Observations for crossing
        obs_records = store.list_observations(crossing_id=crossing_id)
        for obs in obs_records:
            _expand_observation_record(obs, last_event_node)

        # 6. Explicit causal links connected to crossing_id
        links = store.list_causal_links(crossing_id)
        for link in links:
            _process_explicit_link(link, depth)

    def _expand_observation_record(obs: Any, parent_node_id: str | None) -> None:
        if obs.observation_id in visited_observations:
            return
        visited_observations.add(obs.observation_id)

        obs_node_id = obs.observation_id
        summary_text = (
            f"Verifier {obs.verifier_id} checked '{obs.claim}' on "
            f"{obs.subject_resource} -> {obs.status}"
        )
        nodes[obs_node_id] = CausalTraceNode(
            node_id=obs_node_id,
            entity_type="observation",
            role="observation",
            label=f"Obs: {obs.claim} ({obs.status})",
            timestamp=obs.observed_at,
            status=obs.status,
            summary=summary_text,
            metadata={
                "verifier_id": obs.verifier_id,
                "trust_domain": obs.trust_domain,
                "fresh": obs.is_fresh(),
            },
        )
        if parent_node_id:
            edges.append(
                CausalTraceEdge(
                    source_id=parent_node_id,
                    target_id=obs_node_id,
                    relation="verified_by",
                    edge_type="intrinsic",
                )
            )

    def _process_explicit_link(link: CausalLink, depth: int) -> None:
        # Determine causal direction:
        # If relation is 'caused_by': target caused source -> edge is target -> source
        # If relation is 'verifies': source verifies target -> edge is target -> source
        # If relation is 'triggers': source triggers target -> edge is source -> target
        # If relation is 'derived_from': source derived from target -> edge is target -> source
        # If relation is 'part_of': source is part of target -> edge is target -> source
        if link.relation in ("caused_by", "verifies", "derived_from", "part_of"):
            causal_src = link.target_id
            causal_tgt = link.source_id
        else:  # triggers
            causal_src = link.source_id
            causal_tgt = link.target_id

        edges.append(
            CausalTraceEdge(
                source_id=causal_src,
                target_id=causal_tgt,
                relation=link.relation,
                edge_type="explicit",
            )
        )

        # Ensure linked nodes exist or are expanded
        for ent_id, ent_type in [
            (link.source_id, link.source_type),
            (link.target_id, link.target_type),
        ]:
            if ent_id not in nodes:
                if ent_type == "crossing":
                    _expand_crossing(ent_id, depth + 1)
                elif ent_type == "observation":
                    obs = store.get_observation(ent_id)
                    if obs:
                        _expand_observation_record(obs, None)
                    else:
                        missing_refs.append(ent_id)
                elif ent_type == "task":
                    nodes[ent_id] = CausalTraceNode(
                        node_id=ent_id,
                        entity_type="task",
                        role="task",
                        label=f"Task {ent_id}",
                        timestamp=link.created_at,
                        status="active",
                        summary=f"Parent Task Workflow ({ent_id})",
                    )

    # Begin expansion from root
    if resolved_root_type == "crossing":
        _expand_crossing(root_id, 0)
    elif resolved_root_type == "observation":
        obs = store.get_observation(root_id)
        if obs:
            if obs.crossing_id:
                _expand_crossing(obs.crossing_id, 0)
            else:
                _expand_observation_record(obs, None)
        else:
            missing_refs.append(root_id)
    elif resolved_root_type == "task":
        nodes[root_id] = CausalTraceNode(
            node_id=root_id,
            entity_type="task",
            role="task",
            label=f"Task {root_id}",
            timestamp=utc_iso(),
            status="active",
            summary=f"Task Workflow ({root_id})",
        )
        task_links = store.list_causal_links(root_id)
        for link in task_links:
            _process_explicit_link(link, 0)

    # Cycle check
    has_cycles = detect_cycles(edges)

    # Build chronological timeline with causal role priority
    role_priority = {
        "task": 0,
        "proposal": 1,
        "decision": 2,
        "approval": 3,
        "outcome": 4,
        "observation": 5,
    }

    def _sort_key(node: CausalTraceNode) -> tuple[str, int]:
        return (node.timestamp, role_priority.get(node.role, 99))

    sorted_nodes = sorted(nodes.values(), key=_sort_key)
    timeline: list[CausalTimelineEvent] = []
    for idx, node in enumerate(sorted_nodes, start=1):
        # Infer authority label
        if node.role == "proposal":
            authority = "caller_asserted"
        elif node.role == "decision":
            authority = "policy_kernel"
        elif node.role == "approval":
            authority = "operator_human"
        elif node.role == "outcome":
            authority = str(node.metadata.get("authority", "executor_observed"))
        elif node.role == "observation":
            authority = str(node.metadata.get("trust_domain", "verifier_observed"))
        else:
            authority = "workflow_coordinator"

        timeline.append(
            CausalTimelineEvent(
                step=idx,
                timestamp=node.timestamp,
                entity_id=node.node_id,
                role=node.role,
                summary=node.summary,
                authority=authority,
            )
        )

    return CausalTrace(
        root_id=root_id,
        root_type=resolved_root_type,
        nodes=list(nodes.values()),
        edges=edges,
        timeline=timeline,
        dag_verified=not has_cycles,
        missing_references=missing_refs,
    )
