"""Model-agnostic client interfaces for the real-agent demonstration.

The model's only role is to propose actions (OpenAI-compatible tool calls) or
produce a final natural-language answer. Actentra remains solely responsible for
authorization, execution, postcondition verification, and receipt recording.
"""

from __future__ import annotations

import contextlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class SystemResourceReport:
    """Snapshot of host compute resources to avoid OOM when selecting local models."""

    total_ram_gb: float | None
    available_ram_gb: float | None
    cpu_logical: int | None
    recommended_ollama_model: str
    advisory: str


def check_system_resources() -> SystemResourceReport:
    """Inspect available RAM and CPU cores and recommend a safe local model size."""
    cpu_count = os.cpu_count()
    total_gb: float | None = None
    avail_gb: float | None = None
    with contextlib.suppress(Exception):
        import psutil  # type: ignore[import-untyped]

        vm = psutil.virtual_memory()
        total_gb = round(vm.total / (1024**3), 2)
        avail_gb = round(vm.available / (1024**3), 2)

    if avail_gb is None:
        rec = "qwen2.5:1.5b"
        advisory = (
            "psutil unavailable; defaulting to lightweight qwen2.5:1.5b recommendation "
            "to avoid memory pressure."
        )
    elif avail_gb < 4.0:
        rec = "qwen2.5:1.5b"
        advisory = (
            f"Only {avail_gb:.2f} GB RAM available; use a <=1.5B quantized model "
            "(or a remote OpenAI-compatible endpoint) to avoid OOM."
        )
    elif avail_gb < 8.0:
        rec = "qwen2.5:3b"
        advisory = (
            f"{avail_gb:.2f} GB RAM available; qwen2.5:3b or qwen2.5:1.5b fits safely "
            "without GPU or swap pressure."
        )
    else:
        rec = "qwen2.5:7b"
        advisory = f"{avail_gb:.2f} GB RAM available; up to 7B quantized models fit comfortably."

    return SystemResourceReport(
        total_ram_gb=total_gb,
        available_ram_gb=avail_gb,
        cpu_logical=cpu_count,
        recommended_ollama_model=rec,
        advisory=advisory,
    )


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """Normalized assistant turn returned by a ModelClient."""

    content: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class ModelClient(Protocol):
    """Protocol for any replaceable LLM backend that proposes OpenAI-format tool calls."""

    @property
    def model_name(self) -> str: ...

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelResponse: ...


class OpenAICompatibleModelClient:
    """Stdlib HTTP client for any OpenAI-compatible ``/v1/chat/completions`` endpoint.

    Works with local Ollama (``http://127.0.0.1:11434/v1``), LM Studio, vLLM,
    or hosted OpenAI-compatible endpoints. Credentials are read only from
    ``api_key`` or environment variable ``ACTENTRA_DEMO_API_KEY`` and are never
    logged or persisted in Actentra receipts.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        raw_url = (
            base_url
            or os.environ.get("ACTENTRA_DEMO_BASE_URL")
            or "http://127.0.0.1:11434/v1"
        ).rstrip("/")
        self._endpoint = (
            raw_url if raw_url.endswith("/chat/completions") else f"{raw_url}/chat/completions"
        )
        if not self._endpoint.startswith(("http://", "https://")):
            raise ValueError(
                f"Model endpoint must use http:// or https:// scheme, got {self._endpoint!r}"
            )
        self._model = model or os.environ.get("ACTENTRA_DEMO_MODEL") or "qwen2.5:3b"
        self._api_key = api_key if api_key is not None else os.environ.get("ACTENTRA_DEMO_API_KEY")
        self._timeout = timeout_seconds

    @property
    def model_name(self) -> str:
        return self._model

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelResponse:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0.0,
        }
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        req = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            self._endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"Model endpoint HTTP {exc.code} at {self._endpoint}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Could not reach model endpoint {self._endpoint}: {exc.reason}"
            ) from exc

        choices = body.get("choices") or []
        if not choices:
            raise RuntimeError("Model endpoint returned no choices")
        msg = choices[0].get("message") or {}
        raw_calls = msg.get("tool_calls") or []
        return ModelResponse(
            content=msg.get("content"),
            tool_calls=list(raw_calls),
        )


class ScriptedToolProposalModel:
    """Deterministic offline model backend for reproducible tests and demos.

    Emits standard OpenAI-format ``tool_calls`` on the first turn of each task
    and summarizes the Actentra-mediated tool response on the following turn.
    """

    def __init__(
        self,
        proposals_by_task: dict[str, list[dict[str, Any]]] | None = None,
        *,
        model_id: str = "scripted-tool-proposer-v1",
    ) -> None:
        self._model_id = model_id
        self._proposals = dict(proposals_by_task or {})
        self._call_counter = 0

    @property
    def model_name(self) -> str:
        return self._model_id

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelResponse:
        del tools
        # If the last message is a tool result, summarize what happened.
        if messages and messages[-1].get("role") == "tool":
            tool_summaries = [
                m.get("content", "")
                for m in messages
                if m.get("role") == "tool"
            ]
            return ModelResponse(
                content="Completed tool interaction. Last tool output: " + tool_summaries[-1],
                tool_calls=[],
            )

        user_msgs = [m.get("content", "") for m in messages if m.get("role") == "user"]
        latest_task = str(user_msgs[-1]) if user_msgs else ""
        for task_key, calls in self._proposals.items():
            if task_key in latest_task:
                formatted: list[dict[str, Any]] = []
                for call in calls:
                    self._call_counter += 1
                    formatted.append(
                        {
                            "id": f"call_scripted_{self._call_counter}",
                            "type": "function",
                            "function": {
                                "name": call["name"],
                                "arguments": json.dumps(call.get("arguments", {})),
                            },
                        }
                    )
                return ModelResponse(content=None, tool_calls=formatted)

        return ModelResponse(
            content="No tool proposal matched the requested task.",
            tool_calls=[],
        )
