"""Session budget and cumulative limits tracker for Actentra.

Defends against:
- T4: Exfiltration through chains of benign calls (slow-drip data exfiltration)
- T5: Runaway loops, recursion bombs, and cost blowups
"""

from __future__ import annotations

import contextlib
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from actentra_core.envelope import ActionEnvelope
from actentra_core.verdict import Decision, Verdict

_DEFAULT_MAX_TRACKED_SESSIONS = 500


@dataclass(frozen=True, slots=True)
class SessionBudgetConfig:
    """Configurable cumulative limits per session and per principal."""

    max_actions: int | None = None
    max_external_calls: int | None = None
    max_write_bytes: int | None = None
    principal_max_actions: int | None = None
    principal_max_external_calls: int | None = None
    principal_max_write_bytes: int | None = None
    on_exceeded: Verdict = Verdict.ASK

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SessionBudgetConfig | None:
        if not data or not isinstance(data, dict):
            return None
        max_act = data.get("max_actions")
        max_ext = data.get("max_external_calls")
        max_wr = data.get("max_write_bytes")
        p_max_act = data.get("principal_max_actions")
        p_max_ext = data.get("principal_max_external_calls")
        p_max_wr = data.get("principal_max_write_bytes")
        raw_exc = str(data.get("on_exceeded", "ask")).lower().strip()
        try:
            verdict = Verdict(raw_exc)
        except ValueError:
            verdict = Verdict.ASK

        return cls(
            max_actions=int(max_act) if max_act is not None else None,
            max_external_calls=int(max_ext) if max_ext is not None else None,
            max_write_bytes=int(max_wr) if max_wr is not None else None,
            principal_max_actions=int(p_max_act) if p_max_act is not None else None,
            principal_max_external_calls=int(p_max_ext) if p_max_ext is not None else None,
            principal_max_write_bytes=int(p_max_wr) if p_max_wr is not None else None,
            on_exceeded=verdict,
        )


class SessionUsage:
    __slots__ = ("actions_count", "external_calls_count", "write_bytes_count")

    def __init__(self) -> None:
        self.actions_count = 0
        self.external_calls_count = 0
        self.write_bytes_count = 0


class SessionBudgetTracker:
    """Memory-bounded cumulative session and principal budget tracker with SQLite persistence."""

    def __init__(
        self,
        config: SessionBudgetConfig | None = None,
        *,
        max_sessions: int = _DEFAULT_MAX_TRACKED_SESSIONS,
        receipt_store: Any | None = None,
    ) -> None:
        self._config = config
        self._max_sessions = max_sessions
        self._sessions: OrderedDict[str, SessionUsage] = OrderedDict()
        self._principals: OrderedDict[str, SessionUsage] = OrderedDict()
        self._receipt_store = receipt_store
        self._lock = threading.RLock()

    @property
    def config(self) -> SessionBudgetConfig | None:
        return self._config

    def set_config(self, config: SessionBudgetConfig | None) -> None:
        self._config = config

    def set_receipt_store(self, store: Any | None) -> None:
        """Attach receipt store for durable budget persistence across restarts."""
        self._receipt_store = store

    def _get_usage(self, session_id: str) -> SessionUsage:
        if session_id in self._sessions:
            self._sessions.move_to_end(session_id)
            return self._sessions[session_id]

        if len(self._sessions) >= self._max_sessions:
            self._sessions.popitem(last=False)

        usage = SessionUsage()
        if self._receipt_store is not None:
            with contextlib.suppress(Exception):
                persisted = self._receipt_store.get_session_usage(session_id)
                usage.actions_count = persisted.get("actions_count", 0)
                usage.external_calls_count = persisted.get("external_calls_count", 0)
                usage.write_bytes_count = persisted.get("write_bytes_count", 0)

        self._sessions[session_id] = usage
        return usage

    def _get_principal_usage(self, principal_id: str) -> SessionUsage:
        clean_pid = principal_id.strip()
        if clean_pid in self._principals:
            self._principals.move_to_end(clean_pid)
            return self._principals[clean_pid]

        if len(self._principals) >= self._max_sessions:
            self._principals.popitem(last=False)

        usage = SessionUsage()
        if self._receipt_store is not None:
            with contextlib.suppress(Exception):
                persisted = self._receipt_store.get_principal_usage(clean_pid)
                usage.actions_count = persisted.get("actions_count", 0)
                usage.external_calls_count = persisted.get("external_calls_count", 0)
                usage.write_bytes_count = persisted.get("write_bytes_count", 0)

        self._principals[clean_pid] = usage
        return usage

    def get_session_stats(self, session_id: str) -> dict[str, int]:
        """Return current cumulative usage for a session."""
        usage = self._get_usage(session_id)
        return {
            "actions_count": usage.actions_count,
            "external_calls_count": usage.external_calls_count,
            "write_bytes_count": usage.write_bytes_count,
        }

    def get_principal_stats(self, principal_id: str) -> dict[str, int]:
        """Return current cumulative usage for a principal across all sessions."""
        usage = self._get_principal_usage(principal_id)
        return {
            "actions_count": usage.actions_count,
            "external_calls_count": usage.external_calls_count,
            "write_bytes_count": usage.write_bytes_count,
        }

    def check_budget(
        self,
        envelope: ActionEnvelope,
        principal_id: str | None = None,
    ) -> Decision | None:
        """Check if an envelope would violate cumulative session or principal budgets."""
        if self._config is None:
            return None

        with self._lock:
            cfg = self._config
            usage = self._get_usage(envelope.session_id)
            eff_principal = principal_id or (envelope.agent.id if envelope.agent else None)
            p_usage = self._get_principal_usage(eff_principal) if eff_principal else None

        tool = envelope.action.tool
        is_external = tool.startswith(("http.", "net.http", "webhook.", "api."))
        write_bytes = 0
        if isinstance(envelope.action.params, dict):
            raw_data = envelope.action.params.get("content") or envelope.action.params.get("data")
            if isinstance(raw_data, (str, bytes)):
                write_bytes = len(raw_data)

        # 1. Total actions budget (session-level)
        if cfg.max_actions is not None and usage.actions_count >= cfg.max_actions:
            return Decision(
                verdict=cfg.on_exceeded,
                rule_id="budget:max-actions-exceeded",
                reason=(
                    f"Session cumulative actions limit ({cfg.max_actions}) exceeded "
                    f"[current={usage.actions_count}]"
                ),
                policy_version="kernel:budget",
                canonical_hash=envelope.canonical_hash,
                risk_tags=("runaway-loop", "budget-exceeded"),
            )

        # 2. Total actions budget (principal-level)
        if (
            cfg.principal_max_actions is not None
            and p_usage is not None
            and p_usage.actions_count >= cfg.principal_max_actions
        ):
            return Decision(
                verdict=cfg.on_exceeded,
                rule_id="budget:principal-max-actions-exceeded",
                reason=(
                    f"Principal cumulative actions limit ({cfg.principal_max_actions}) "
                    f"exceeded across sessions [current={p_usage.actions_count}]"
                ),
                policy_version="kernel:budget",
                canonical_hash=envelope.canonical_hash,
                risk_tags=("runaway-loop", "budget-exceeded", "principal-quota-exceeded"),
            )

        # 3. External egress calls budget (session-level)
        if (
            cfg.max_external_calls is not None
            and is_external
            and usage.external_calls_count >= cfg.max_external_calls
        ):
            return Decision(
                verdict=cfg.on_exceeded,
                rule_id="budget:max-external-calls-exceeded",
                reason=(
                    f"Session cumulative external calls limit ({cfg.max_external_calls}) "
                    f"exceeded [current={usage.external_calls_count}]"
                ),
                policy_version="kernel:budget",
                canonical_hash=envelope.canonical_hash,
                risk_tags=("external-egress", "budget-exceeded"),
            )

        # 4. External egress calls budget (principal-level)
        if (
            cfg.principal_max_external_calls is not None
            and is_external
            and p_usage is not None
            and p_usage.external_calls_count >= cfg.principal_max_external_calls
        ):
            return Decision(
                verdict=cfg.on_exceeded,
                rule_id="budget:principal-max-external-calls-exceeded",
                reason=(
                    f"Principal cumulative external calls limit "
                    f"({cfg.principal_max_external_calls}) exceeded "
                    f"[current={p_usage.external_calls_count}]"
                ),
                policy_version="kernel:budget",
                canonical_hash=envelope.canonical_hash,
                risk_tags=("external-egress", "budget-exceeded", "principal-quota-exceeded"),
            )

        # 5. Write bytes budget (session-level)
        if (
            cfg.max_write_bytes is not None
            and (usage.write_bytes_count + write_bytes) > cfg.max_write_bytes
        ):
            return Decision(
                verdict=cfg.on_exceeded,
                rule_id="budget:max-write-bytes-exceeded",
                reason=(
                    f"Session cumulative write bytes limit ({cfg.max_write_bytes} bytes) "
                    f"exceeded [current={usage.write_bytes_count}, requested={write_bytes}]"
                ),
                policy_version="kernel:budget",
                canonical_hash=envelope.canonical_hash,
                risk_tags=("destructive", "budget-exceeded"),
            )

        # 6. Write bytes budget (principal-level)
        if (
            cfg.principal_max_write_bytes is not None
            and p_usage is not None
            and (p_usage.write_bytes_count + write_bytes) > cfg.principal_max_write_bytes
        ):
            return Decision(
                verdict=cfg.on_exceeded,
                rule_id="budget:principal-max-write-bytes-exceeded",
                reason=(
                    f"Principal cumulative write bytes limit "
                    f"({cfg.principal_max_write_bytes} bytes) exceeded across sessions "
                    f"[current={p_usage.write_bytes_count}, requested={write_bytes}]"
                ),
                policy_version="kernel:budget",
                canonical_hash=envelope.canonical_hash,
                risk_tags=("destructive", "budget-exceeded", "principal-quota-exceeded"),
            )

        return None

    def record_usage(
        self,
        envelope: ActionEnvelope,
        principal_id: str | None = None,
        *,
        bytes_written: int = 0,
    ) -> None:
        """Increment cumulative counters upon successful action evaluation/execution."""
        with self._lock:
            usage = self._get_usage(envelope.session_id)
            eff_principal = principal_id or (envelope.agent.id if envelope.agent else None)
            p_usage = self._get_principal_usage(eff_principal) if eff_principal else None

            delta_actions = 1
            delta_ext = 0
            delta_bytes = 0

            usage.actions_count += 1
            if p_usage is not None:
                p_usage.actions_count += 1

            tool = envelope.action.tool
            if tool.startswith(("http.", "net.http", "webhook.", "api.")):
                usage.external_calls_count += 1
                if p_usage is not None:
                    p_usage.external_calls_count += 1
                delta_ext = 1
            if bytes_written > 0:
                usage.write_bytes_count += bytes_written
                if p_usage is not None:
                    p_usage.write_bytes_count += bytes_written
                delta_bytes = bytes_written
            elif isinstance(envelope.action.params, dict):
                raw_data = envelope.action.params.get("content") or envelope.action.params.get(
                    "data"
                )
                if isinstance(raw_data, (str, bytes)):
                    wb = len(raw_data)
                    usage.write_bytes_count += wb
                    if p_usage is not None:
                        p_usage.write_bytes_count += wb
                    delta_bytes = wb

            if self._receipt_store is not None:
                with contextlib.suppress(Exception):
                    if hasattr(self._receipt_store, "record_budget_usage"):
                        self._receipt_store.record_budget_usage(
                            envelope.session_id,
                            eff_principal,
                            delta_actions=delta_actions,
                            delta_external=delta_ext,
                            delta_bytes=delta_bytes,
                        )
                    else:
                        self._receipt_store.record_session_usage(
                            envelope.session_id,
                            delta_actions=delta_actions,
                            delta_external=delta_ext,
                            delta_bytes=delta_bytes,
                        )
