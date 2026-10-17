"""Safeguard orchestration and trace production."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from traceguard.policy.authorization import duplicate_mutation, output
from traceguard.policy.engine import DeterministicPolicy
from traceguard.sandbox.runner import ContainerRunner, SandboxUnavailable
from traceguard.supervisor.base import Supervisor, merge_outputs
from traceguard.supervisor.contracts import (
    SupervisorSchemaError,
    _validate_arguments_against_json_schema,
    validate_replacement,
)
from traceguard.tools.registry import ToolRegistry
from traceguard.types import (
    Decision,
    ExecutionPlan,
    ExecutionTarget,
    Observation,
    PostRunAssessment,
    PostRunDisposition,
    SafeguardConfig,
    SupervisorOutput,
    TaskAuthority,
    ToolCall,
    TraceEvent,
    TrustLabel,
)


class RuntimeResult:
    def __init__(
        self,
        trace: TraceEvent,
        observation: Observation | None,
        post_run: PostRunAssessment | None = None,
    ) -> None:
        self.trace = trace
        self.observation = observation
        self.post_run = post_run


class TraceGuardRuntime:
    def __init__(
        self,
        tools: ToolRegistry,
        config: SafeguardConfig,
        policy: DeterministicPolicy | None = None,
        supervisor: Supervisor | None = None,
        sandbox: ContainerRunner | None = None,
        task_authority: TaskAuthority | None = None,
    ) -> None:
        self.tools = tools
        self.config = config
        self.policy = policy
        self.supervisor = supervisor
        self.sandbox = sandbox
        self.task_authority = task_authority or TaskAuthority()
        self.executed_calls: dict[str, list[ToolCall]] = {}
        self.escalated_tasks: set[str] = set()
        if self.policy is not None:
            self.policy.task_authority = self.task_authority
        if config.deterministic_policy and policy is None:
            raise ValueError("deterministic policy is enabled but unavailable")
        if config.llm_supervisor and supervisor is None:
            raise ValueError("LLM supervisor is enabled but unavailable")

    def execute_call(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> RuntimeResult:
        started = time.monotonic()
        if call.task_id in self.escalated_tasks:
            denied = output(
                Decision.ESCALATE, "episode-escalated", "Episode requires human review."
            )
            return RuntimeResult(
                self._trace(call, call, [denied], None, None, started, "ESCALATE"), None
            )
        self._set_supervisor_context(call)
        outputs = self._evaluate(user_task, call, observations)
        merged = merge_outputs(outputs)
        effective_call = (
            merged.rewritten_call if merged and merged.decision is Decision.REWRITE else call
        )
        if merged and merged.decision in {Decision.BLOCK, Decision.ESCALATE}:
            trace = self._trace(
                call, effective_call, outputs, None, None, started, merged.decision.value
            )
            return RuntimeResult(trace, None)

        original_rewrite = merged if merged and merged.decision is Decision.REWRITE else None
        if original_rewrite:
            try:
                validate_replacement(
                    call,
                    effective_call,
                    goal=user_task,
                    observations=observations,
                    authority=self.task_authority,
                    schemas=self.tools.schemas(),
                )
            except SupervisorSchemaError:
                return RuntimeResult(
                    self._trace(call, effective_call, outputs, None, None, started, "ESCALATE"),
                    None,
                )
            self._set_supervisor_context(effective_call, rewritten=True)
            reevaluated = self._evaluate(user_task, effective_call, observations)
            outputs.extend(reevaluated)
            second = merge_outputs(reevaluated)
            if second and second.decision in {Decision.BLOCK, Decision.ESCALATE, Decision.REWRITE}:
                outcome = (
                    "ESCALATE" if second.decision is Decision.REWRITE else second.decision.value
                )
                trace = self._trace(call, effective_call, outputs, None, None, started, outcome)
                return RuntimeResult(trace, None)
            merged = second or original_rewrite

        target = (
            merged.execution_target
            if merged and merged.execution_target
            else original_rewrite.execution_target
            if original_rewrite and original_rewrite.execution_target
            else ExecutionTarget.DEFAULT
        )
        profile = (
            merged.container_profile
            if merged and merged.container_profile
            else original_rewrite.container_profile
            if original_rewrite
            else None
        )
        plan = ExecutionPlan(
            effective_call=effective_call,
            target=target,
            sandbox_profile=profile,
            declared_input_paths=[
                resource.removeprefix("input:")
                for resource in effective_call.requested_resources
                if resource.startswith("input:")
            ],
            validated=True,
            validation_reason="approved safeguard merge",
        )
        if target is ExecutionTarget.SIMULATED or (
            effective_call.tool_name == "restricted_command" and target is ExecutionTarget.DEFAULT
        ):
            # A simulation must never reach a real handler or execution ledger.
            plan.target = ExecutionTarget.SIMULATED
            observation = Observation(
                content='{"status":"simulated","host_execution":false}',
                source_type="simulation",
                source_id=call.call_id,
                trust=TrustLabel.UNTRUSTED_TOOL,
                may_contain_instructions=False,
                provenance_chain=[*call.consumed_observation_ids, call.call_id],
            )
            return RuntimeResult(
                self._trace(call, effective_call, outputs, plan, observation, started, "SIMULATED"),
                observation,
            )
        if target is ExecutionTarget.CONTAINER:
            if self.sandbox is None:
                trace = self._trace(call, effective_call, outputs, plan, None, started, "ESCALATE")
                return RuntimeResult(trace, None)
            try:
                evidence = self.sandbox.execute(plan)
            except SandboxUnavailable:
                trace = self._trace(call, effective_call, outputs, plan, None, started, "ESCALATE")
                return RuntimeResult(trace, None)
            self.executed_calls.setdefault(call.task_id, []).append(effective_call)
            observation = Observation(
                content=evidence.model_dump_json(),
                source_type="sandbox",
                source_id=call.call_id,
                trust=TrustLabel.UNTRUSTED_TOOL,
                provenance_chain=[*call.consumed_observation_ids, call.call_id],
                may_contain_instructions=True,
            )
            post_run = None
            if self.config.post_run_reevaluation and self.supervisor:
                post_run = self.supervisor.reevaluate(user_task, effective_call, evidence)
            if post_run and post_run.disposition is not PostRunDisposition.ACCEPT_RESULT:
                outcome = (
                    "ESCALATE"
                    if post_run.disposition
                    in {PostRunDisposition.ESCALATE, PostRunDisposition.REWRITE_AND_RETRY}
                    else "BLOCK_RESULT"
                )
                trace = self._trace(
                    call,
                    effective_call,
                    outputs,
                    plan,
                    observation,
                    started,
                    outcome,
                )
                return RuntimeResult(trace, None, post_run)
            trace = self._trace(
                call, effective_call, outputs, plan, observation, started, "EXECUTED_CONTAINER"
            )
            return RuntimeResult(trace, observation, post_run)

        try:
            observation = self.tools.execute(effective_call)
        except (KeyError, OSError, SyntaxError, TypeError, ValueError) as exc:
            observation = Observation(
                content=f"{type(exc).__name__}: {exc}",
                source_type="tool_error",
                source_id=call.call_id,
                trust=TrustLabel.TRUSTED_TOOL,
                provenance_chain=[*call.consumed_observation_ids, call.call_id],
                may_contain_instructions=False,
            )
            trace = self._trace(
                call,
                effective_call,
                outputs,
                plan,
                observation,
                started,
                "TOOL_ERROR",
            )
            return RuntimeResult(trace, observation)
        self.executed_calls.setdefault(call.task_id, []).append(effective_call)
        outcome = (
            "SIMULATED"
            if effective_call.tool_name == "restricted_command"
            or target is ExecutionTarget.SIMULATED
            else "EXECUTED"
        )
        trace = self._trace(call, effective_call, outputs, plan, observation, started, outcome)
        return RuntimeResult(trace, observation)

    def _set_supervisor_context(self, call: ToolCall, *, rewritten: bool = False) -> None:
        if self.policy is not None:
            self.policy.previous_calls = self.executed_calls.get(call.task_id, [])
        if self.supervisor is not None and hasattr(self.supervisor, "set_context"):
            self.supervisor.set_context(
                previous_calls=self.executed_calls.get(call.task_id, []),
                task_authority=self.task_authority,
                trusted_policy=self.policy.config.model_dump(mode="json") if self.policy else None,
                step_already_rewritten=rewritten,
            )

    def _evaluate(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> list[SupervisorOutput]:
        outputs: list[SupervisorOutput] = []
        if self.config.deterministic_policy or self.config.llm_supervisor:
            repeated = duplicate_mutation(
                call, self.executed_calls.get(call.task_id, []), self.task_authority
            )
            if repeated is not None:
                return [repeated]
            try:
                schemas = self.tools.schemas()
                if call.tool_name not in schemas:
                    raise SupervisorSchemaError("tool schema unavailable")
                _validate_arguments_against_json_schema(call.arguments, schemas[call.tool_name])
            except SupervisorSchemaError:
                return [output(Decision.ESCALATE, "invalid-tool-schema", "Tool validation failed.")]
        if self.config.deterministic_policy:
            assert self.policy is not None
            deterministic = self.policy.evaluate(user_task, call, observations)
            outputs.append(deterministic)
            if deterministic.decision in {Decision.BLOCK, Decision.ESCALATE}:
                return outputs
        if self.config.llm_supervisor:
            assert self.supervisor is not None
            outputs.append(self.supervisor.evaluate(user_task, call, observations))
        return outputs

    def _trace(
        self,
        proposed: ToolCall,
        effective: ToolCall,
        outputs: list[SupervisorOutput],
        plan: ExecutionPlan | None,
        observation: Observation | None,
        started: float,
        outcome: str,
    ) -> TraceEvent:
        if outcome == "ESCALATE":
            self.escalated_tasks.add(proposed.task_id)
        digest = hashlib.sha256(observation.content.encode()).hexdigest() if observation else None
        token_usage = sum(
            int(output.provider_metadata.get("prompt_eval_count") or 0)
            + int(output.provider_metadata.get("eval_count") or 0)
            for output in outputs
        )
        return TraceEvent(
            task_id=proposed.task_id,
            step_id=proposed.step_id,
            proposed_call=proposed,
            effective_call=effective,
            safeguard_outputs=outputs,
            execution_plan=plan,
            result_observation_id=observation.observation_id if observation else None,
            result_digest=digest,
            latency_ms=(time.monotonic() - started) * 1000,
            token_usage=token_usage,
            policy_version=self.policy.version if self.policy else "disabled",
            episode_outcome=outcome,
        )


def build_system_prompt(defensive: bool) -> str:
    data = Path(__file__).parent / "data" / "prompts"
    base = (data / "base_system.txt").read_text(encoding="utf-8").strip()
    if not defensive:
        return base
    defense = (data / "defensive_system.txt").read_text(encoding="utf-8").strip()
    return f"{base}\n\n{defense}"
