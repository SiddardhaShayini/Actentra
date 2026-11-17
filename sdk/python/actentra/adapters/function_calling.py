"""OpenAI/Anthropic-style function calling adapter for Actentra."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from actentra.boundary import ActionBlockedError, Boundary
from actentra_core.canonicalize import canonicalize_json
from actentra_core.envelope import ProvenanceItem

ResourceFn = Callable[[dict[str, Any]], str]


def _infer_verb_from_name(name: str) -> str:
    n = name.lower()
    if n.startswith(("read", "get", "list", "fetch", "search", "view", "describe")):
        return "read"
    if n.startswith(("delete", "remove", "drop", "destroy", "purge")):
        return "delete"
    if n.startswith(("write", "edit", "create", "update", "set", "save", "insert", "append")):
        return "write"
    if n.startswith(("exec", "run", "bash", "sh", "cmd", "powershell")):
        return "exec"
    if n.startswith(("http", "curl", "post", "webhook", "email")):
        return "network"
    return "other"


def _default_resource_extractor(args: dict[str, Any], fallback_tool: str) -> str:
    for key in ("resource", "path", "file_path", "target_path", "filepath", "url", "endpoint"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            if key in ("path", "file_path", "target_path", "filepath") and not val.startswith(
                "path:"
            ):
                return f"path:{val}"
            return val
    return f"tool:{fallback_tool}"


@dataclass(frozen=True, slots=True)
class ProtectedTool:
    name: str
    fn: Callable[..., Any]
    verb: str
    resource_fn: ResourceFn
    description: str = ""


class FunctionCallAdapter:
    """Intermediary mediating agent tool calls (e.g. OpenAI function-calling format)."""

    def __init__(
        self,
        boundary: Boundary,
        *,
        raise_on_blocked: bool = False,
    ) -> None:
        self._boundary = boundary
        self._raise_on_blocked = raise_on_blocked
        self._tools: dict[str, ProtectedTool] = {}

    @property
    def boundary(self) -> Boundary:
        return self._boundary

    def register_tool(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        verb: str | None = None,
        resource_fn: ResourceFn | None = None,
        description: str = "",
    ) -> None:
        """Register a Python callable under a tool name."""
        clean_name = name.strip()
        inferred_verb = verb or _infer_verb_from_name(clean_name)
        res_fn = resource_fn or (lambda args: _default_resource_extractor(args, clean_name))

        self._tools[clean_name] = ProtectedTool(
            name=clean_name,
            fn=fn,
            verb=inferred_verb,
            resource_fn=res_fn,
            description=description,
        )

    def execute_call(
        self,
        tool_call: dict[str, Any],
        *,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> dict[str, Any]:
        """Execute a tool call dict and return an OpenAI-compatible tool response message.

        Supports both standard OpenAI format:
            {"id": "call_1", "type": "function", "function": {"name": "..", "arguments": "{}"}}
        and direct format:
            {"name": "...", "arguments": {...}}
        """
        call_id = str(tool_call.get("id") or "call_default")

        # Resolve name & arguments from either format
        fn_part = tool_call.get("function")
        if isinstance(fn_part, dict):
            raw_name = str(fn_part.get("name", ""))
            raw_args = fn_part.get("arguments", {})
        else:
            raw_name = str(tool_call.get("name", ""))
            raw_args = tool_call.get("arguments", {})

        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args) if raw_args.strip() else {}
            except json.JSONDecodeError as exc:
                return self._error_response(call_id, f"Invalid JSON in tool arguments: {exc}")
        elif isinstance(raw_args, dict):
            args = dict(raw_args)
        else:
            args = {}

        tool_obj = self._tools.get(raw_name)
        if tool_obj is None:
            err_msg = f"Tool '{raw_name}' is not registered with Actentra FunctionCallAdapter"
            if self._raise_on_blocked:
                raise KeyError(err_msg)
            return self._error_response(call_id, err_msg)

        try:
            resource = tool_obj.resource_fn(args)
        except Exception as exc:
            err_msg = f"Failed to compute resource identifier for '{raw_name}': {exc}"
            if self._raise_on_blocked:
                raise
            return self._error_response(call_id, err_msg)

        try:
            result = self._boundary.execute(
                tool=tool_obj.name,
                verb=tool_obj.verb,
                resource=resource,
                params=args,
                fn=lambda _env, _dec: self._invoke_callable(tool_obj.fn, args),
                provenance=provenance,
                user_goal=user_goal,
            )
            content_str = (
                canonicalize_json(result) if isinstance(result, (dict, list)) else str(result)
            )
            return {
                "role": "tool",
                "tool_call_id": call_id,
                "content": content_str,
                "is_error": False,
            }
        except ActionBlockedError as exc:
            if self._raise_on_blocked:
                raise
            return self._error_response(call_id, f"Blocked by Actentra policy: {exc}")
        except Exception as exc:
            if self._raise_on_blocked:
                raise
            return self._error_response(call_id, f"Tool execution failed: {type(exc).__name__}")

    def _invoke_callable(self, fn: Callable[..., Any], args: dict[str, Any]) -> Any:
        sig = inspect.signature(fn)
        # Check if function takes **kwargs
        has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        if has_varkw:
            return fn(**args)
        # Filter to declared params only
        filtered = {k: v for k, v in args.items() if k in sig.parameters}
        return fn(**filtered)

    def _error_response(self, call_id: str, error_message: str) -> dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": call_id,
            "content": json.dumps({"error": error_message}),
            "is_error": True,
        }
