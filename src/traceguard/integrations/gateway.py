from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from traceguard.policy.authorization import duplicate_mutation, output
from traceguard.policy.kernel import CompiledAuthority
from traceguard.supervisor.base import Supervisor, enforce_allow_invariants
from traceguard.supervisor.contracts import (
    SupervisorSchemaError,
    _validate_arguments_against_json_schema,
    validate_replacement,
)
from traceguard.supervisor.deterministic import DeterministicSupervisor
from traceguard.types import (
    Decision,
    Observation,
    SupervisorOutput,
    TaskAuthority,
    ToolCall,
    TrustLabel,
)


class SupervisionGateway:
    """Framework-neutral pre-tool supervision boundary."""

    def __init__(
        self,
        *,
        mode: str,
        supervisor: Supervisor | None = None,
        available_tools: Mapping[str, dict[str, Any]] | None = None,
        task_authority: TaskAuthority | None = None,
    ) -> None:
        if mode == "none":
            raise ValueError("strict authority cannot disable enforcement")
        if mode not in {"deterministic", "llm", "deterministic_llm"}:
            raise ValueError(f"unknown supervisor mode: {mode}")
        if task_authority is None or task_authority.enforcement_mode != "strict":
            raise ValueError("application-owned strict authority is required")
        self.mode = mode
        self.task_authority = task_authority.model_copy(deep=True)
        self.history: list[ToolCall] = []
        self.escalated = False
        if supervisor is None and mode == "deterministic":
            supervisor = DeterministicSupervisor()
        if supervisor is None and mode in {"llm", "deterministic_llm"}:
            raise ValueError("LLM modes require an explicit supervisor")
        self.supervisor = supervisor
        self.available_tools = dict(available_tools or {})
        self.compiled = CompiledAuthority.compile(self.task_authority, self.available_tools)

    def evaluate(
        self,
        *,
        task_id: str,
        step_id: int,
        user_goal: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        observations: list[Observation],
        requested_resources: list[str] | None = None,
    ) -> tuple[ToolCall, SupervisorOutput]:
        call = ToolCall(
            task_id=task_id,
            step_id=step_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            consumed_observation_ids=[item.observation_id for item in observations],
            requested_resources=list(requested_resources or []),
        )
        if hasattr(self.supervisor, "last_evaluation_log"):
            self.supervisor.last_evaluation_log = None
        if self.escalated:
            return call, output(
                Decision.ESCALATE, "episode-escalated", "Task requires human review."
            )
        if self.compiled is not None:
            checked = self.compiled.evaluate(user_goal, call, observations, self.history)
            if checked.decision is not Decision.ALLOW:
                self.escalated = checked.decision is Decision.ESCALATE
                return call, checked
            call = self.compiled.normalize_read(call)
        repeated = duplicate_mutation(call, self.history, self.task_authority)
        if repeated is not None:
            return call, repeated
        if hasattr(self.supervisor, "available_tools"):
            self.supervisor.available_tools = self.available_tools
        if hasattr(self.supervisor, "set_context"):
            self.supervisor.set_context(
                previous_calls=self.history, task_authority=self.task_authority
            )
        try:
            if call.tool_name not in self.available_tools:
                raise SupervisorSchemaError("tool schema unavailable")
            _validate_arguments_against_json_schema(
                call.arguments, self.available_tools[call.tool_name]
            )
        except SupervisorSchemaError:
            self.escalated = True
            return call, output(Decision.ESCALATE, "invalid-tool-schema", "Tool validation failed.")
        if self.mode == "deterministic_llm":
            gate = DeterministicSupervisor()
            gate.available_tools = self.available_tools
            gate.set_context(previous_calls=self.history, task_authority=self.task_authority)
            checked = gate.evaluate(user_goal, call, observations)
            if checked.decision in {Decision.BLOCK, Decision.ESCALATE}:
                self.escalated = checked.decision is Decision.ESCALATE
                return call, checked
        decision = self.supervisor.evaluate(user_goal, call, observations)
        if decision.decision is Decision.REWRITE and decision.rewritten_call is not None:
            replacement = decision.rewritten_call
            try:
                validate_replacement(
                    call,
                    replacement,
                    goal=user_goal,
                    observations=observations,
                    authority=self.task_authority,
                    schemas=self.available_tools,
                )
            except SupervisorSchemaError:
                self.escalated = True
                return call, output(
                    Decision.ESCALATE, "invalid-rewrite", "Rewrite validation failed."
                )
            if hasattr(self.supervisor, "set_context"):
                self.supervisor.set_context(
                    previous_calls=self.history,
                    task_authority=self.task_authority,
                    step_already_rewritten=True,
                )
            checked = duplicate_mutation(replacement, self.history, self.task_authority)
            if checked is None and self.compiled is not None:
                checked = self.compiled.evaluate(user_goal, replacement, observations, self.history)
                if checked.decision is Decision.ALLOW:
                    checked = None
            if checked is None and self.mode == "deterministic_llm":
                gate = DeterministicSupervisor()
                gate.available_tools = self.available_tools
                gate.set_context(previous_calls=self.history, task_authority=self.task_authority)
                checked = gate.evaluate(user_goal, replacement, observations)
                if checked.decision is Decision.ALLOW:
                    checked = None
            checked = checked or self.supervisor.evaluate(user_goal, replacement, observations)
            if checked.decision is Decision.ALLOW:
                call = replacement
                decision = checked
            else:
                decision = checked.model_copy(
                    update={"decision": Decision.ESCALATE, "rewritten_call": None}
                )
        decision = enforce_allow_invariants(decision)
        if decision.decision is Decision.ESCALATE:
            self.escalated = True
        return call, decision

    def observation(
        self,
        call: ToolCall,
        content: str,
        *,
        source_type: str,
        trust: TrustLabel = TrustLabel.UNTRUSTED_TOOL,
    ) -> Observation:
        self.history.append(call)
        return Observation(
            content=content,
            source_type=source_type,
            source_id=call.call_id,
            trust=trust,
            provenance_chain=[*call.consumed_observation_ids, call.call_id],
            may_contain_instructions=trust
            in {TrustLabel.UNTRUSTED_DOCUMENT, TrustLabel.UNTRUSTED_TOOL},
        )
