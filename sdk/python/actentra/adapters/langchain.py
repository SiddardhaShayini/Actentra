"""LangChain tool adapter for Actentra."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from actentra.adapters.function_calling import _default_resource_extractor, _infer_verb_from_name
from actentra.boundary import Boundary
from actentra_core.envelope import ProvenanceItem

ResourceFn = Callable[[dict[str, Any]], str]


class LangChainToolWrapper:
    """Wraps any LangChain BaseTool, structured tool, or callable with Actentra enforcement."""

    def __init__(
        self,
        tool: Any,
        boundary: Boundary,
        *,
        tool_name: str | None = None,
        verb: str | None = None,
        resource_fn: ResourceFn | None = None,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> None:
        self._underlying = tool
        self._boundary = boundary
        fallback_name = getattr(tool, "__name__", "unnamed_tool")
        resolved_name = tool_name or getattr(tool, "name", fallback_name)
        self.name: str = str(resolved_name)
        desc = getattr(tool, "description", getattr(tool, "__doc__", "") or "")
        self.description: str = str(desc)
        self.verb: str = verb or _infer_verb_from_name(self.name)
        self.resource_fn: ResourceFn = resource_fn or (
            lambda args: _default_resource_extractor(args, self.name)
        )
        self._provenance = tuple(provenance)
        self._user_goal = user_goal

    @property
    def underlying(self) -> Any:
        return self._underlying

    @property
    def boundary(self) -> Boundary:
        return self._boundary

    def _normalize_args(self, input_val: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
        if isinstance(input_val, dict):
            merged = dict(input_val)
            merged.update(kwargs)
            return merged
        if input_val is not None:
            # Single argument passed (e.g. query string)
            merged = {"input": input_val}
            merged.update(kwargs)
            return merged
        return dict(kwargs)

    def _execute_underlying(self, input_val: Any, kwargs: dict[str, Any]) -> Any:
        actual_input = kwargs if input_val is None and kwargs else input_val
        # Check if underlying tool has an .invoke() method (standard modern LangChain)
        if hasattr(self._underlying, "invoke") and callable(self._underlying.invoke):
            config = kwargs.get("config") if isinstance(kwargs, dict) else None
            if config is not None:
                return self._underlying.invoke(actual_input, config=config)
            return self._underlying.invoke(actual_input)
        # Check if underlying tool has a .run() method (legacy LangChain)
        if hasattr(self._underlying, "run") and callable(self._underlying.run):
            if input_val is not None and kwargs:
                return self._underlying.run(input_val, **kwargs)
            if input_val is not None:
                return self._underlying.run(input_val)
            return self._underlying.run(**kwargs)
        # Direct callable fallback
        if callable(self._underlying):
            if isinstance(actual_input, dict) and not (input_val and kwargs):
                return self._underlying(**actual_input)
            if input_val is not None:
                return self._underlying(input_val, **kwargs)
            return self._underlying(**kwargs)
        raise TypeError(f"Underlying tool {self._underlying!r} is not callable")

    def invoke(self, input: Any = None, config: Any = None, **kwargs: Any) -> Any:
        """Mediate LangChain tool invoke() call through Actentra boundary."""
        args_dict = self._normalize_args(input, kwargs)
        resource = self.resource_fn(args_dict)

        extra_call_kwargs = dict(kwargs)
        if config is not None:
            extra_call_kwargs["config"] = config

        return self._boundary.execute(
            tool=self.name,
            verb=self.verb,
            resource=resource,
            params=args_dict,
            fn=lambda _env, _dec: self._execute_underlying(input, extra_call_kwargs),
            provenance=self._provenance,
            user_goal=self._user_goal,
        )

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Mediate LangChain tool run() call through Actentra boundary."""
        first_arg = args[0] if args else None
        return self.invoke(first_arg, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        first_arg = args[0] if args else None
        return self.invoke(first_arg, **kwargs)


def wrap_langchain_tool(
    tool: Any,
    boundary: Boundary,
    *,
    tool_name: str | None = None,
    verb: str | None = None,
    resource_fn: ResourceFn | None = None,
    provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
    user_goal: str | None = None,
) -> LangChainToolWrapper:
    """Convenience helper to wrap a LangChain tool with an Actentra Boundary."""
    return LangChainToolWrapper(
        tool=tool,
        boundary=boundary,
        tool_name=tool_name,
        verb=verb,
        resource_fn=resource_fn,
        provenance=provenance,
        user_goal=user_goal,
    )
