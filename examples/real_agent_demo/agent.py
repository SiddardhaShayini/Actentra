"""Minimal model-agnostic tool-calling agent governed by Actentra."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from examples.real_agent_demo.actentra_layer import (
    ActentraToolBridge,
    MediatedToolCall,
    build_agent_tool_schemas,
)
from examples.real_agent_demo.model_client import ModelClient

_SYSTEM_PROMPT = (
    "You are a workspace assistant. Use the provided tools to fulfill the user's request. "
    "All tool executions are mediated by Actentra; if an action is blocked or fails verification, "
    "report the exact status honestly without claiming it succeeded."
)


@dataclass(frozen=True, slots=True)
class AgentRunReport:
    """Complete record of one agent task execution and all Actentra-mediated calls."""

    task: str
    model_name: str
    final_answer: str
    mediated_calls: list[MediatedToolCall]


class ToolCallingAgent:
    """OpenAI-compatible tool-calling agent with zero unmediated tool paths."""

    def __init__(self, model: ModelClient, bridge: ActentraToolBridge) -> None:
        self._model = model
        self._bridge = bridge
        self._tools = build_agent_tool_schemas()

    def run(self, task: str, *, max_steps: int = 6) -> AgentRunReport:
        """Run the agent loop for ``task``, mediating every tool call via Actentra."""
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": task},
        ]
        mediated: list[MediatedToolCall] = []

        for _ in range(max_steps):
            response = self._model.chat(messages, self._tools)
            if not response.tool_calls:
                return AgentRunReport(
                    task=task,
                    model_name=self._model.model_name,
                    final_answer=response.content or "",
                    mediated_calls=mediated,
                )

            messages.append(
                {
                    "role": "assistant",
                    "content": response.content,
                    "tool_calls": response.tool_calls,
                }
            )
            for call in response.tool_calls:
                outcome = self._bridge.dispatch_tool_call(call)
                mediated.append(outcome)
                messages.append(outcome.to_tool_message())

        return AgentRunReport(
            task=task,
            model_name=self._model.model_name,
            final_answer="Reached maximum tool-calling steps.",
            mediated_calls=mediated,
        )
