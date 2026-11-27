"""Actentra enforcement bridge for the real-agent demonstration.

Every tool call proposed by the agent is routed strictly through ``Boundary.run()``
with ``LocalFSExecutor`` and ``WorkspaceFileVerifier``. The agent never receives
direct filesystem or subprocess handles.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from actentra import (
    Boundary,
    CanonicalizationError,
    CrossingReceipt,
    ExecutionResult,
    VerificationResult,
    path_resource,
)
from actentra_core.envelope import ActionEnvelope
from actentra_core.verdict import Decision


@dataclass(frozen=True, slots=True)
class MediatedToolCall:
    """Record of a single model tool proposal and Actentra's enforcement outcome."""

    tool_call_id: str
    agent_tool: str
    arguments: dict[str, Any]
    actentra_tool: str
    verb: str
    resource: str
    execution: ExecutionResult | None
    pre_evaluation_error: str | None = None

    def to_tool_message(self) -> dict[str, Any]:
        """Serialize into an OpenAI-compatible ``role='tool'`` response message."""
        if self.pre_evaluation_error is not None:
            payload = {
                "allowed": False,
                "status": "rejected_pre_evaluation",
                "verified": False,
                "error": self.pre_evaluation_error,
            }
        elif self.execution is None:
            payload = {
                "allowed": False,
                "status": "error",
                "verified": False,
                "error": "No execution result produced",
            }
        else:
            payload = {
                "crossing_id": self.execution.crossing_id,
                "allowed": self.execution.allowed,
                "verdict": self.execution.verdict.value,
                "rule_id": self.execution.rule_id,
                "reason": self.execution.reason,
                "status": self.execution.status,
                "evidence_status": self.execution.evidence_status,
                "verified": self.execution.verified,
                "canonical_hash": self.execution.canonical_hash,
                "result": self.execution.result if self.execution.allowed else None,
            }
        return {
            "role": "tool",
            "tool_call_id": self.tool_call_id,
            "content": json.dumps(payload, default=str),
        }


def build_agent_tool_schemas() -> list[dict[str, Any]]:
    """Return OpenAI-compatible function tool definitions exposed to the AI agent."""
    return [
        {
            "type": "function",
            "function": {
                "name": "list_workspace_files",
                "description": "List files inside the authorized workspace directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": (
                                "Relative directory path inside workspace (default '.')."
                            ),
                        }
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_workspace_file",
                "description": "Read a text file inside the authorized workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Relative path inside the workspace.",
                        }
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "write_workspace_file",
                "description": "Write a text file inside the authorized workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Relative path inside the workspace.",
                        },
                        "content": {
                            "type": "string",
                            "description": "UTF-8 text content to write.",
                        },
                    },
                    "required": ["path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "delete_workspace_file",
                "description": "Delete a file inside the authorized workspace (requires approval).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Relative path inside the workspace.",
                        }
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "unreliable_write_file",
                "description": (
                    "Test-only unreliable file writer that may claim success without writing."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Relative path inside the workspace.",
                        },
                        "content": {
                            "type": "string",
                            "description": "UTF-8 text content intended to be written.",
                        },
                    },
                    "required": ["path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_shell_command",
                "description": "Attempt to run a shell command (prohibited by policy).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Shell command string.",
                        }
                    },
                    "required": ["command"],
                },
            },
        },
    ]


class ActentraToolBridge:
    """Single mandatory enforcement boundary mediating all agent tool calls."""

    def __init__(
        self,
        *,
        policy_yaml: str,
        receipts_db: Path,
        workspace_root: Path,
        session_id: str = "real-agent-demo-session",
        agent_id: str = "real-tool-agent",
        model_name: str = "unknown",
    ) -> None:
        self._workspace_root = workspace_root.resolve()
        self._boundary = Boundary.from_yaml(
            policy_yaml=policy_yaml,
            receipts_db=receipts_db,
            workspace_root=self._workspace_root,
            session_id=session_id,
            agent_id=agent_id,
            framework="openai-tool-calling",
            model=model_name,
        )
        # Controlled test executor for Scenario C: claims success without touching disk.
        self._boundary.register_executor("unreliable.fs_write", self._false_success_executor)
        # Prohibited tool placeholder (policy denies shell.exec before any executor runs).
        self._boundary.register_executor("shell.exec", self._prohibited_shell_stub)

    @property
    def boundary(self) -> Boundary:
        return self._boundary

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root

    @staticmethod
    def _false_success_executor(envelope: ActionEnvelope, decision: Decision) -> dict[str, Any]:
        del decision
        return {
            "written": True,
            "claimed_path": envelope.action.resource,
            "note": "Simulated buggy executor: returned success without writing bytes.",
        }

    @staticmethod
    def _prohibited_shell_stub(envelope: ActionEnvelope, decision: Decision) -> dict[str, Any]:
        del envelope, decision
        raise RuntimeError("shell.exec must never be permitted by policy")

    def grant_approval(self, canonical_hash: str) -> None:
        """Grant a single-use, hash-bound human approval for a held ASK action."""
        self._boundary.grant_approval(canonical_hash=canonical_hash)

    def inspect_crossing(self, crossing_id: str) -> CrossingReceipt:
        return self._boundary.inspect_crossing(crossing_id)

    def verify_audit_log(self) -> VerificationResult:
        return self._boundary.verify_receipts(verify_envelopes=True)

    def _resolve_workspace_resource(self, raw_path: str) -> str:
        # Preserve explicit absolute paths so out-of-workspace proposals reach
        # Actentra policy evaluation and get recorded in durable DENY receipts.
        candidate = Path(raw_path)
        if candidate.is_absolute():
            return path_resource(candidate)
        return path_resource(raw_path, workspace_root=self._workspace_root)

    def dispatch_tool_call(self, tool_call: dict[str, Any]) -> MediatedToolCall:
        """Validate, authorize, execute, and verify one OpenAI-format tool call."""
        call_id = str(tool_call.get("id") or "call_unknown")
        raw_fn = tool_call.get("function")
        fn_part: dict[str, Any] = raw_fn if isinstance(raw_fn, dict) else {}
        agent_tool = str(fn_part.get("name") or tool_call.get("name") or "").strip()
        raw_args = fn_part.get("arguments", tool_call.get("arguments", {}))

        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args) if raw_args.strip() else {}
            except json.JSONDecodeError as exc:
                return MediatedToolCall(
                    tool_call_id=call_id,
                    agent_tool=agent_tool,
                    arguments={},
                    actentra_tool="unknown",
                    verb="other",
                    resource="invalid:json",
                    execution=None,
                    pre_evaluation_error=f"Invalid JSON arguments: {exc}",
                )
        elif isinstance(raw_args, dict):
            args = dict(raw_args)
        else:
            args = {}

        try:
            mapped = self._map_tool_call(agent_tool, args)
        except (CanonicalizationError, ValueError) as exc:
            return MediatedToolCall(
                tool_call_id=call_id,
                agent_tool=agent_tool,
                arguments=args,
                actentra_tool="rejected",
                verb="other",
                resource=str(args.get("path", "")),
                execution=None,
                pre_evaluation_error=f"Fail-closed input/canonicalization error: {exc}",
            )

        actentra_tool, verb, resource, params = mapped
        exec_res = self._boundary.run(
            tool=actentra_tool,
            verb=verb,
            resource=resource,
            params=params,
            verify_postcondition=True,
            raise_on_blocked=False,
            raise_on_postcondition_failure=False,
        )
        return MediatedToolCall(
            tool_call_id=call_id,
            agent_tool=agent_tool,
            arguments=args,
            actentra_tool=actentra_tool,
            verb=verb,
            resource=resource,
            execution=exec_res,
        )

    def _map_tool_call(
        self, agent_tool: str, args: dict[str, Any]
    ) -> tuple[str, str, str, dict[str, Any]]:
        if agent_tool == "list_workspace_files":
            rel = str(args.get("path") or ".")
            resource = self._resolve_workspace_resource(rel)
            return "fs.list", "read", resource, {"path": rel}

        if agent_tool == "read_workspace_file":
            rel = str(args.get("path") or "")
            if not rel:
                raise ValueError("Missing required parameter 'path'")
            resource = self._resolve_workspace_resource(rel)
            return "fs.read", "read", resource, {"path": rel}

        if agent_tool == "write_workspace_file":
            rel = str(args.get("path") or "")
            content = str(args.get("content") or "")
            if not rel:
                raise ValueError("Missing required parameter 'path'")
            resource = self._resolve_workspace_resource(rel)
            return (
                "fs.write",
                "write",
                resource,
                {"path": rel, "content": content, "create_parents": True},
            )

        if agent_tool == "delete_workspace_file":
            rel = str(args.get("path") or "")
            if not rel:
                raise ValueError("Missing required parameter 'path'")
            resource = self._resolve_workspace_resource(rel)
            return "fs.delete", "delete", resource, {"path": rel}

        if agent_tool == "unreliable_write_file":
            rel = str(args.get("path") or "")
            content = str(args.get("content") or "")
            if not rel:
                raise ValueError("Missing required parameter 'path'")
            resource = self._resolve_workspace_resource(rel)
            return (
                "unreliable.fs_write",
                "write",
                resource,
                {"path": rel, "content": content},
            )

        if agent_tool == "run_shell_command":
            cmd = str(args.get("command") or "")
            return "shell.exec", "exec", "shell:local", {"command": cmd}

        raise ValueError(f"Unknown agent tool: {agent_tool!r}")
