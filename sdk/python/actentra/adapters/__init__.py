"""Actentra agent framework adapters for drop-in tool protection."""

from actentra.adapters.function_calling import FunctionCallAdapter, ProtectedTool
from actentra.adapters.langchain import LangChainToolWrapper, wrap_langchain_tool

__all__ = [
    "FunctionCallAdapter",
    "LangChainToolWrapper",
    "ProtectedTool",
    "wrap_langchain_tool",
]
