"""Safeguard orchestration and trace production."""

from __future__ import annotations

import hashlib
import time
from copy import copy
from decimal import Decimal
from pathlib import Path
from threading import RLock

from traceguard.control.service import AuthorizationError
from traceguard.control.signing import canonical
from traceguard.ledger import ExecutionLedger, ExecutionUnknown
from traceguard.policy.authorization import duplicate_mutation, output, tool_effect
from traceguard.policy.engine import DeterministicPolicy
from traceguard.policy.kernel import CompiledAuthority
from traceguard.sandbox.runner import ContainerRunner, SandboxUnavailable
from traceguard.supervisor.base import Supervisor, merge_outputs
from traceguard.supervisor.contracts import (
    SupervisorSchemaError,
    _validate_arguments_against_json_schema,
    validate_replacement,
)
from traceguard.supervisor.redaction import redact_value
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
        effect_ledger: ExecutionLedger | None = None,
        bound_task_id: str | None = None,
        result_policy_version: str = "embedded-result-v1",
    ) -> None:
        self._lock = RLock()
        self.effect_ledger = effect_ledger
        self.bound_task_id = bound_task_id
        if not result_policy_version:
            raise ValueError("result policy version must be explicit and nonempty")
        self.result_policy_version = result_policy_version
        self.tools = tools
        self.config = config.model_copy(deep=True)
        self.policy = copy(policy) if policy is not None else None
        self.supervisor = copy(supervisor) if supervisor is not None else None
        self.sandbox = sandbox
        self.task_authority = (task_authority or TaskAuthority()).model_copy(deep=True)
        self.compiled_authority = (
            CompiledAuthority.compile(self.task_authority, tools.schemas())
            if self.task_authority.enforcement_mode == "strict"
            else None
        )
        if effect_ledger is not None and self.compiled_authority is None:
            raise ValueError("embedded effect ledger requires explicit strict authority")
        self.executed_calls: dict[str, list[ToolCall]] = {}
        self.escalated_tasks: set[str] = set()
        if self.policy is not None:
            self.policy.config = self.policy.config.model_copy(deep=True)
            self.policy.task_authority = self.task_authority
        if config.deterministic_policy and policy is None:
            raise ValueError("deterministic policy is enabled but unavailable")
        if config.llm_supervisor and supervisor is None:
            raise ValueError("LLM supervisor is enabled but unavailable")

    def execute_call(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> RuntimeResult:
        with self._lock:
            return self._execute_call(
                user_task,
                call.model_copy(deep=True),
                [item.model_copy(deep=True) for item in observations],
            )

    def _execute_call(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> RuntimeResult:
        started = time.monotonic()
        if self.bound_task_id is not None and call.task_id != self.bound_task_id:
            denied = output(Decision.BLOCK, "wrong-task", "Task ID differs from approved scope.")
            return RuntimeResult(
                self._trace(call, call, [denied], None, None, started, "BLOCK"), None
            )
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
        reserved = False
        result_policy = hashlib.sha256(
            canonical(
                {
                    "version": self.result_policy_version,
                    "authority": self.compiled_authority.digest
                    if self.compiled_authority
                    else None,
                    "post_run": self.config.post_run_reevaluation,
                    "policy": self.policy.config.model_dump(mode="json") if self.policy else None,
                }
            )
        ).hexdigest()
        if self.effect_ledger is not None and tool_effect(effective_call) in {"mutate", "command"}:
            payload = {
                "tool": effective_call.tool_name,
                "arguments": effective_call.arguments,
                "resources": effective_call.requested_resources,
                "task": effective_call.task_id,
            }
            digest = hashlib.sha256(canonical(payload)).hexdigest()
            try:
                replay = self.effect_ledger.reserve(
                    scope=("embedded", "application", self.compiled_authority.digest, call.task_id),
                    nonce=effective_call.call_id,
                    idempotency_key=effective_call.call_id,
                    digest=digest,
                    effect_digest=digest,
                    amount=Decimal(str(effective_call.arguments.get("amount", 0))),
                    budget_limit=(
                        str(self.task_authority.max_amount)
                        if self.task_authority.max_amount is not None
                        else None
                    ),
                    repeatable=effective_call.tool_name in self.task_authority.repeatable_tools,
                    result_policy=result_policy,
                )
                if replay is not None:
                    if replay["disposition"] != "accepted_for_agent" or replay["result"] is None:
                        outcome = (
                            "BLOCK_RESULT" if replay["disposition"] == "withheld" else "ESCALATE"
                        )
                        return RuntimeResult(
                            self._trace(
                                call,
                                effective_call,
                                outputs,
                                plan,
                                None,
                                started,
                                outcome,
                                execution_status="replayed",
                            ),
                            None,
                        )
                    observation = Observation.model_validate_json(replay["result"])
                    return RuntimeResult(
                        self._trace(
                            call, effective_call, outputs, plan, observation, started, "REPLAYED"
                        ),
                        observation,
                    )
                reserved = True
            except (ExecutionUnknown, AuthorizationError):
                return RuntimeResult(
                    self._trace(call, effective_call, outputs, plan, None, started, "ESCALATE"),
                    None,
                )
        if target is ExecutionTarget.CONTAINER:
            if self.sandbox is None:
                if reserved:
                    self.effect_ledger.finish(effective_call.call_id, "not_dispatched")
                trace = self._trace(call, effective_call, outputs, plan, None, started, "ESCALATE")
                return RuntimeResult(trace, None)
            try:
                evidence = self.sandbox.execute(plan)
            except SandboxUnavailable:
                if reserved:
                    self.effect_ledger.finish(effective_call.call_id, "unknown")
                trace = self._trace(
                    call,
                    effective_call,
                    outputs,
                    plan,
                    None,
                    started,
                    "ESCALATE",
                    execution_status="unknown",
                )
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
            if reserved:
                self.effect_ledger.finish(
                    effective_call.call_id,
                    "succeeded",
                    self._receipt(observation),
                    disposition="pending_review"
                    if self.config.post_run_reevaluation
                    else "accepted_for_agent",
                )
            post_run = None
            if self.config.post_run_reevaluation:
                try:
                    if self.supervisor is None:
                        raise ValueError("post-run review requires a supervisor")
                    post_run = self.supervisor.reevaluate(user_task, effective_call, evidence)
                    if post_run is None:
                        raise ValueError("post-run review returned no disposition")
                except Exception:
                    if reserved:
                        self.effect_ledger.decide_result(
                            effective_call.call_id, "review_required", result_policy=result_policy
                        )
                    return RuntimeResult(
                        self._trace(
                            call,
                            effective_call,
                            outputs,
                            plan,
                            observation,
                            started,
                            "ESCALATE",
                            execution_status="dispatched",
                        ),
                        None,
                    )
                if reserved:
                    disposition = (
                        "accepted_for_agent"
                        if post_run.disposition is PostRunDisposition.ACCEPT_RESULT
                        else "withheld"
                        if post_run.disposition is PostRunDisposition.BLOCK_RESULT
                        else "review_required"
                    )
                    self.effect_ledger.decide_result(
                        effective_call.call_id, disposition, result_policy=result_policy
                    )
            if post_run and post_run.disposition is not PostRunDisposition.ACCEPT_RESULT:
                if post_run.disposition is PostRunDisposition.BLOCK_RESULT and hasattr(
                    self.sandbox, "reject_artifacts"
                ):
                    self.sandbox.reject_artifacts(evidence)
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
            consequential = tool_effect(effective_call) in {"mutate", "command"}
            if reserved:
                self.effect_ledger.finish(effective_call.call_id, "unknown")
            if consequential:
                self.executed_calls.setdefault(call.task_id, []).append(effective_call)
                self.escalated_tasks.add(call.task_id)
            observation = Observation(
                content=(
                    "Effect outcome unknown; reconcile before retry."
                    if consequential
                    else f"{type(exc).__name__}: {redact_value(str(exc))}"
                ),
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
                "EXECUTION_UNKNOWN" if consequential else "TOOL_ERROR",
            )
            return RuntimeResult(trace, observation)
        except BaseException:
            if reserved:
                self.effect_ledger.finish(effective_call.call_id, "unknown")
            raise
        if reserved:
            self.effect_ledger.finish(
                effective_call.call_id,
                "succeeded",
                self._receipt(observation),
                disposition="accepted_for_agent",
            )
        self.executed_calls.setdefault(call.task_id, []).append(effective_call)
        outcome = (
            "SIMULATED"
            if effective_call.tool_name == "restricted_command"
            or target is ExecutionTarget.SIMULATED
            else "EXECUTED"
        )
        trace = self._trace(call, effective_call, outputs, plan, observation, started, outcome)
        return RuntimeResult(trace, observation)

    @staticmethod
    def _receipt(observation: Observation) -> str:
        import json

        safe = observation.model_copy(deep=True)
        try:
            safe.content = json.dumps(redact_value(json.loads(safe.content)), sort_keys=True)
        except json.JSONDecodeError:
            safe.content = redact_value(safe.content)
        return safe.model_dump_json()

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
        if self.compiled_authority is not None:
            checked = self.compiled_authority.evaluate(
                user_task, call, observations, self.executed_calls.get(call.task_id, [])
            )
            outputs.append(checked)
            if checked.decision in {Decision.BLOCK, Decision.ESCALATE}:
                return outputs
            call = self.compiled_authority.normalize_read(call)
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
        execution_status: str | None = None,
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
            execution_status=(
                execution_status
                or (
                    "unknown"
                    if outcome in {"EXECUTION_UNKNOWN", "TOOL_ERROR"}
                    else "replayed"
                    if outcome == "REPLAYED"
                    else "dispatched"
                    if outcome in {"EXECUTED", "EXECUTED_CONTAINER", "BLOCK_RESULT"}
                    or (
                        outcome == "ESCALATE"
                        and plan is not None
                        and plan.target is ExecutionTarget.CONTAINER
                        and observation is not None
                    )
                    else "not_dispatched"
                )
            ),
            result_released=outcome in {"EXECUTED", "EXECUTED_CONTAINER", "REPLAYED", "SIMULATED"},
        )


def build_system_prompt(defensive: bool) -> str:
    data = Path(__file__).parent / "data" / "prompts"
    base = (data / "base_system.txt").read_text(encoding="utf-8").strip()
    if not defensive:
        return base
    defense = (data / "defensive_system.txt").read_text(encoding="utf-8").strip()
    return f"{base}\n\n{defense}"
