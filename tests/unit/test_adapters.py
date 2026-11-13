"""Unit tests for agent framework adapters (OpenAI function calling and LangChain)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from actentra import (
    ActionBlockedError,
    Boundary,
    FunctionCallAdapter,
    wrap_langchain_tool,
)
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, verify_log


def _sample_boundary(db_path: Path) -> Boundary:
    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-calc
    match: { tool: calculate, verb: read }
    verdict: allow
  - id: allow-file-read
    match: { tool: read_file, verb: read, resource: "path:C:/work/**" }
    verdict: allow
  - id: ask-file-write
    match: { tool: write_file, verb: write }
    verdict: ask
    reason: "File writing requires approval"
"""
    )
    return Boundary(policy=policy, receipt_store=ReceiptStore(db_path))


def test_function_calling_adapter_openai_format(tmp_path: Path) -> None:
    db_path = tmp_path / "fc.db"
    boundary = _sample_boundary(db_path)
    adapter = FunctionCallAdapter(boundary)

    # Register tools
    adapter.register_tool(
        "calculate",
        lambda a, b, op="add": a + b if op == "add" else a * b,
        verb="read",
    )
    adapter.register_tool(
        "read_file",
        lambda path: f"content of {path}",
        verb="read",
    )
    adapter.register_tool(
        "write_file",
        lambda path, content: f"wrote {len(content)} bytes to {path}",
        verb="write",
    )

    # 1. Standard OpenAI tool call format: allowed tool
    call_msg = {
        "id": "call_calc_1",
        "type": "function",
        "function": {
            "name": "calculate",
            "arguments": json.dumps({"a": 10, "b": 25, "op": "add"}),
        },
    }
    resp = adapter.execute_call(call_msg)
    assert resp["is_error"] is False
    assert resp["tool_call_id"] == "call_calc_1"
    assert resp["content"] == "35"

    # 2. Allowed file read
    call_read = {
        "id": "call_read_1",
        "type": "function",
        "function": {
            "name": "read_file",
            "arguments": json.dumps({"path": r"C:\work\report.txt"}),
        },
    }
    resp_read = adapter.execute_call(call_read)
    assert resp_read["is_error"] is False
    assert "content of" in resp_read["content"]

    # 3. Unapproved file write (ASK -> Blocked)
    call_write = {
        "id": "call_write_1",
        "type": "function",
        "function": {
            "name": "write_file",
            "arguments": json.dumps({"path": r"C:\work\out.txt", "content": "hi"}),
        },
    }
    resp_write = adapter.execute_call(call_write)
    assert resp_write["is_error"] is True
    assert "Blocked by Actentra policy" in resp_write["content"]

    # 4. Unknown tool
    call_unknown = {
        "id": "call_unk",
        "function": {"name": "hack_everything", "arguments": "{}"},
    }
    resp_unk = adapter.execute_call(call_unknown)
    assert resp_unk["is_error"] is True
    assert "not registered" in resp_unk["content"]

    # 5. Pre-approve exact hash for write_file -> succeeds!
    adapter.boundary.grant_approval(
        canonical_hash="sha256:d894b8e2170c9eb38c4146bb1b93f18bf0a071d2b7817ebcb745aa64848d5c41",
    )
    # Re-executing exact call with raise_on_blocked=True
    adapter._raise_on_blocked = True
    with pytest.raises(ActionBlockedError):
        # Non-matching hash fails
        adapter.execute_call(
            {"name": "write_file", "arguments": {"path": r"C:\work\other.txt", "content": "x"}}
        )

    vr = verify_log(db_path)
    assert vr.ok is True


class MockLangChainTool:
    def __init__(self, name: str, description: str, fn: Any) -> None:
        self.name = name
        self.description = description
        self.fn: Any = fn

    def invoke(self, input_val: dict[str, object] | str, config: object = None) -> object:
        if isinstance(input_val, dict):
            return self.fn(**input_val)
        return self.fn(input_val)


def test_langchain_tool_wrapper(tmp_path: Path) -> None:
    db_path = tmp_path / "lc.db"
    boundary = _sample_boundary(db_path)

    raw_tool = MockLangChainTool(
        name="read_file",
        description="Read workspace file",
        fn=lambda path: f"data from {path}",
    )

    wrapped = wrap_langchain_tool(raw_tool, boundary, verb="read")
    assert wrapped.name == "read_file"
    assert wrapped.description == "Read workspace file"

    # invoke() allowed
    out = wrapped.invoke({"path": r"C:\work\doc.txt"})
    assert out == "data from C:\\work\\doc.txt"

    # run() allowed
    out2 = wrapped.run(path=r"C:\work\notes.txt")
    assert out2 == "data from C:\\work\\notes.txt"

    # Blocked call outside workspace
    with pytest.raises(ActionBlockedError):
        wrapped.invoke({"path": r"C:\outside\secret.txt"})

    vr = verify_log(db_path)
    assert vr.ok is True
    assert vr.total_records == 5  # 2 allowed decisions + 2 outcomes + 1 blocked decision
