"""Native Inspect API compatibility, without a model or executing tools."""

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("inspect_ai")

from inspect_ai.tool import ToolCall  # noqa: E402

from benchmarks.datasets.inspect_integration import (  # noqa: E402
    inspect_standard_tools,
    traceguard_inspect_approver,
)
from traceguard.types import Decision, RiskLevel  # noqa: E402


def test_standard_tools_construct_with_bounded_single_command_shell():
    tools = inspect_standard_tools(terminal=True, memory=True)
    assert len(tools) == 7
    assert inspect_standard_tools(terminal=False, memory=False) == []


@pytest.mark.parametrize(
    "decision,expected",
    [
        (Decision.ALLOW, "approve"),
        (Decision.BLOCK, "reject"),
        (Decision.ESCALATE, "escalate"),
        (Decision.REWRITE, "modify"),
    ],
)
def test_native_approval_schema_preserves_framework_decisions(decision, expected):
    call = ToolCall(id="fixture", function="read_file", arguments={"file": "old"})
    rewritten = SimpleNamespace(tool_name="read_file", arguments={"file": "approved"})
    output = SimpleNamespace(
        decision=decision, risk=RiskLevel.LOW, reason="schema fixture", rewritten_call=rewritten
    )
    gateway = SimpleNamespace(evaluate=lambda **kw: (SimpleNamespace(call_id="fixture"), output))
    approve = traceguard_inspect_approver(gateway, user_goal="schema fixture")
    result = asyncio.run(approve(None, call, None, []))
    assert result.decision == expected
    if decision is Decision.REWRITE:
        assert result.modified.arguments == {"file": "approved"}
        assert call.arguments == {"file": "old"}
        result.modified.arguments["file"] = "later mutation"
        assert rewritten.arguments == {"file": "approved"}
