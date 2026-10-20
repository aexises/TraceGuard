from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from benchmarks.datasets.gateway import SupervisionGateway
from traceguard.policy.authorization import tool_effect
from traceguard.policy.read_resources import bind_read_schema
from traceguard.types import Decision, Observation, TrustLabel


def inspect_read_schema(tool: Any) -> dict:
    """Bind only actual native ToolDefs whose inspected resource mapping is supported."""
    from inspect_ai.tool import ToolDef

    definition = ToolDef(tool)
    return bind_read_schema(
        definition.parameters.model_dump(mode="json", exclude_none=True),
        adapter_id="inspect-native-v1",
        tool_name=definition.name,
    )


def inspect_standard_tools(
    *,
    terminal: bool,
    memory: bool,
) -> list[Any]:
    """Return maintained Inspect tools; terminal capability is explicit."""
    try:
        from inspect_ai.tool import (
            bash,
            grep,
            list_files,
            python,
            read_file,
            text_editor,
        )
        from inspect_ai.tool import memory as inspect_memory
    except ImportError as exc:
        raise RuntimeError("install TraceGuard with the 'inspect' extra") from exc

    tools: list[Any] = []
    if terminal:
        tools.extend(
            [
                read_file(timeout=30),
                list_files(timeout=30),
                grep(timeout=30),
                text_editor(timeout=30),
                python(timeout=30),
                bash(timeout=30),
            ]
        )
    if memory:
        tools.append(inspect_memory())
    return tools


def traceguard_inspect_approver(
    gateway: SupervisionGateway,
    *,
    user_goal: str | Callable[[], str],
    task_id: str = "inspect-eval",
):
    """Build an Inspect custom approver that delegates every call to TraceGuard."""
    try:
        from inspect_ai.approval import Approval
    except ImportError as exc:
        raise RuntimeError("install TraceGuard with the 'inspect' extra") from exc

    step = 0

    async def approve(message, call, view, history):
        del message, view
        nonlocal step
        goal = user_goal() if callable(user_goal) else user_goal
        observations = _inspect_history_observations(history)
        normalized, decision = gateway.evaluate(
            task_id=task_id,
            step_id=step,
            user_goal=goal,
            tool_name=str(call.function),
            arguments=dict(call.arguments),
            observations=observations,
        )
        step += 1
        metadata = {
            "traceguard_decision": decision.decision.value,
            "traceguard_risk": decision.risk.value,
            "traceguard_reason": decision.reason,
            "traceguard_call_id": normalized.call_id,
        }
        if getattr(gateway, "compiled", None) is not None and tool_effect(normalized) != "read":
            return Approval(
                decision="reject",
                explanation="Strict consequential tools require GuardedInspectExecutor dispatch; "
                "an approval callback cannot observe or account for execution.",
                metadata=metadata,
            )
        if decision.decision is Decision.ALLOW:
            return Approval(decision="approve", explanation=decision.reason, metadata=metadata)
        if decision.decision is Decision.REWRITE and decision.rewritten_call is not None:
            modified = replace(
                call,
                function=decision.rewritten_call.tool_name,
                arguments=deepcopy(decision.rewritten_call.arguments),
            )
            return Approval(
                decision="modify",
                modified=modified,
                explanation=decision.reason,
                metadata=metadata,
            )
        if decision.decision is Decision.ESCALATE:
            return Approval(decision="escalate", explanation=decision.reason, metadata=metadata)
        return Approval(decision="reject", explanation=decision.reason, metadata=metadata)

    return approve


def _inspect_history_observations(history: list[Any]) -> list[Observation]:
    observations: list[Observation] = []
    for index, item in enumerate(history):
        role = str(getattr(item, "role", ""))
        if role != "tool":
            continue
        content = getattr(item, "content", "")
        observations.append(
            Observation(
                content=str(content),
                source_type="inspect_tool",
                source_id=f"inspect-history-{index}",
                observation_id=str(uuid5(NAMESPACE_URL, f"inspect-history-{index}")),
                trust=TrustLabel.UNTRUSTED_TOOL,
                may_contain_instructions=True,
            )
        )
    return observations
