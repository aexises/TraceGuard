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


def test_broader_native_capabilities_require_explicit_research_profile():
    tools = inspect_standard_tools(terminal=True, memory=True, profile="research")
    assert len(tools) == 7
    with pytest.raises(ValueError, match="memory"):
        inspect_standard_tools(terminal=True, memory=True)
    assert inspect_standard_tools(terminal=False, memory=False) == []


def test_every_advertised_strict_tool_has_a_reviewed_resource_mapping():
    from inspect_ai.tool import ToolDef

    from benchmarks.datasets.inspect_integration import inspect_read_schema
    from traceguard.policy.kernel import CompiledAuthority
    from traceguard.types import TaskAuthority
    from traceguard.types import ToolCall as Proposal

    native = inspect_standard_tools(terminal=True, memory=False)
    assert {ToolDef(item).name for item in native} == {"read_file", "list_files", "grep"}
    arguments = {
        "read_file": {"file_path": "fixture.txt"},
        "list_files": {"path": "fixture"},
        "grep": {"path": "fixture.txt", "pattern": "canary"},
    }
    for item in native:
        name = ToolDef(item).name
        field = "file_path" if name == "read_file" else "path"
        scope = TaskAuthority(
            enforcement_mode="strict",
            allowed_tools=[name],
            resource_values={name: {field: [arguments[name][field]]}},
        )
        kernel = CompiledAuthority.compile(scope, {name: inspect_read_schema(item)})
        proposed = Proposal(task_id="task", step_id=0, tool_name=name, arguments=arguments[name])
        assert kernel.evaluate("Read fixture", proposed, []).decision is Decision.ALLOW
        proposed.arguments[field] = "unapproved.txt"
        assert kernel.evaluate("Read fixture", proposed, []).decision is not Decision.ALLOW


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
