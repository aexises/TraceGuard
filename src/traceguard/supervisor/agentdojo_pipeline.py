"""AgentDojo pipeline bridge for TraceGuard supervisors."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from traceguard.policy.authorization import check_authority, duplicate_mutation, output
from traceguard.supervisor.base import enforce_allow_invariants
from traceguard.supervisor.contracts import (
    SupervisorEvaluationLog,
    SupervisorSchemaError,
    _validate_arguments_against_json_schema,
    validate_replacement,
)
from traceguard.supervisor.heuristic import HeuristicSupervisor
from traceguard.supervisor.llm import GeminiSupervisor, OllamaSupervisor, QwenSupervisor
from traceguard.supervisor.redaction import (
    RedactionConfig,
    mandatory_redaction_config,
    redact_value,
)
from traceguard.types import (
    Decision,
    Observation,
    SupervisorOutput,
    TaskAuthority,
    ToolCall,
    TrustLabel,
)


def _redacted_supervisor_log_payload(
    decision_payload: Mapping[str, Any],
    last_evaluation_log: SupervisorEvaluationLog | None,
    redaction_config: RedactionConfig | None,
) -> dict[str, Any]:
    redaction_config = mandatory_redaction_config(redaction_config)
    return redact_value(
        {
            "decision": dict(decision_payload),
            "llm_evaluation": last_evaluation_log.model_dump(mode="json")
            if last_evaluation_log is not None
            else None,
        },
        redaction_config,
    )


def build_supervised_agentdojo_pipeline(
    react_llm,
    *,
    max_steps: int,
    tool_output_format: str | None,
    supervisor_name: str,
    supervisor_model: str,
    supervisor_url: str,
    supervisor_max_retries: int,
    supervisor_timeout: float,
    supervisor_confidence_threshold: float,
    supervisor_enable_rewrite: bool,
    supervisor_deterministic_enabled: bool,
    supervisor_log_path: Path | None,
    gemini_api_key: str | None,
    gemini_base_url: str | None,
    ollama_url: str,
    camera_log_steps: bool = False,
    seed: int = 0,
    redaction_config: RedactionConfig | None = None,
    system_prompt: str | None = None,
    task_authority: TaskAuthority | None = None,
    max_block_replans: int = 2,
):
    """Build an AgentDojo pipeline with TraceGuard between LLM and tools."""

    redaction_config = mandatory_redaction_config(redaction_config)

    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import (
        ToolsExecutionLoop,
        ToolsExecutor,
        tool_result_to_str,
    )
    from agentdojo.types import text_content_block_from_string

    if tool_output_format == "json":

        def formatter(result):
            return json.dumps(result, default=str)
    else:
        formatter = tool_result_to_str

    if supervisor_name == "deterministic":
        supervisor = AgentDojoDeterministicSupervisor()
    elif supervisor_name in {"ollama", "qwen", "llm", "deterministic_llm"}:
        provider = OllamaSupervisor(
            model=supervisor_model,
            url=supervisor_url or ollama_url,
            max_transport_retries=supervisor_max_retries,
            timeout=supervisor_timeout,
            seed=seed,
            redaction_config=redaction_config,
        )
        deterministic_enabled = supervisor_deterministic_enabled and supervisor_name not in {"llm"}
        supervisor = QwenSupervisor(
            provider=provider,
            confidence_threshold=supervisor_confidence_threshold,
            enable_rewrite=supervisor_enable_rewrite,
            deterministic_enabled=deterministic_enabled,
        )
    elif supervisor_name == "gemini":
        supervisor = QwenSupervisor(
            provider=GeminiSupervisor(
                model=supervisor_model,
                api_key=gemini_api_key,
                base_url=gemini_base_url,
                timeout=supervisor_timeout,
                max_transport_retries=supervisor_max_retries,
                redaction_config=redaction_config,
            ),
            confidence_threshold=supervisor_confidence_threshold,
            enable_rewrite=supervisor_enable_rewrite,
            deterministic_enabled=supervisor_deterministic_enabled,
        )
    else:
        supervisor = HeuristicSupervisor()

    class TraceGuardAgentDojoSupervisor(BasePipelineElement):
        name = f"traceguard-{supervisor_name}-supervisor"

        def query(
            self,
            query,
            runtime,
            env=None,
            messages=(),
            extra_args=None,
        ):
            if extra_args is None:
                extra_args = {}
            if extra_args.get("traceguard_stopped"):
                return query, runtime, env, messages, extra_args
            if not messages or messages[-1]["role"] != "assistant":
                return query, runtime, env, messages, extra_args

            tool_calls = messages[-1].get("tool_calls") or []
            if not tool_calls:
                return query, runtime, env, messages, extra_args

            observations = self._observations(messages[:-1])
            approved = []
            pending_calls: list[ToolCall] = []
            decisions = []
            for index, tool_call in enumerate(tool_calls):
                if hasattr(supervisor, "last_evaluation_log"):
                    supervisor.last_evaluation_log = None
                if not tool_call.id:
                    tool_call.id = str(uuid5(NAMESPACE_URL, f"{query}:{len(messages)}:{index}"))
                call = ToolCall(
                    task_id=str(query)[:80] or "agentdojo",
                    step_id=len(observations) + index,
                    tool_name=tool_call.function,
                    arguments=dict(tool_call.args),
                    consumed_observation_ids=[
                        observation.observation_id for observation in observations
                    ],
                )
                if hasattr(supervisor, "available_tools"):
                    supervisor.available_tools = self._tool_schemas(runtime.functions)

                if hasattr(supervisor, "set_context"):
                    supervisor.set_context(
                        previous_calls=_executed_calls(messages[:-1]),
                        task_authority=task_authority or TaskAuthority(),
                    )
                try:
                    schema = self._tool_schemas(runtime.functions).get(call.tool_name)
                    if schema is None:
                        raise SupervisorSchemaError("tool schema unavailable")
                    _validate_arguments_against_json_schema(call.arguments, schema)
                    repeated = duplicate_mutation(
                        call,
                        [*_executed_calls(messages[:-1]), *pending_calls],
                        task_authority or TaskAuthority(),
                    )
                    reserved = None
                    if pending_calls and getattr(supervisor, "deterministic_enabled", False):
                        reserved = check_authority(
                            str(query),
                            call,
                            observations,
                            task_authority,
                            [*_executed_calls(messages[:-1]), *pending_calls],
                        )
                    decision = (
                        repeated or reserved or supervisor.evaluate(str(query), call, observations)
                    )
                except SupervisorSchemaError:
                    decision = output(
                        Decision.ESCALATE, "invalid-tool-schema", "Tool validation failed."
                    )

                if decision.decision is Decision.REWRITE and decision.rewritten_call is not None:
                    replacement = decision.rewritten_call
                    if hasattr(supervisor, "set_context"):
                        supervisor.set_context(
                            previous_calls=_executed_calls(messages[:-1]),
                            task_authority=task_authority or TaskAuthority(),
                            step_already_rewritten=True,
                        )
                    try:
                        validate_replacement(
                            call,
                            replacement,
                            goal=str(query),
                            observations=observations,
                            authority=task_authority or TaskAuthority(),
                            schemas=self._tool_schemas(runtime.functions),
                        )
                        checked = duplicate_mutation(
                            replacement,
                            [*_executed_calls(messages[:-1]), *pending_calls],
                            task_authority or TaskAuthority(),
                        )
                        if checked is None and getattr(supervisor, "deterministic_enabled", False):
                            checked = check_authority(
                                str(query),
                                replacement,
                                observations,
                                task_authority,
                                [*_executed_calls(messages[:-1]), *pending_calls],
                            )
                        checked = checked or supervisor.evaluate(
                            str(query), replacement, observations
                        )
                    except SupervisorSchemaError:
                        checked = output(
                            Decision.ESCALATE, "invalid-rewrite", "Rewrite validation failed."
                        )
                    if checked.decision is Decision.ALLOW:
                        tool_call.function = replacement.tool_name
                        tool_call.args = replacement.arguments
                        decision = checked
                    else:
                        decision = checked.model_copy(
                            update={"decision": Decision.ESCALATE, "rewritten_call": None}
                        )
                decision = enforce_allow_invariants(decision)
                decision_payload = decision.model_dump(mode="json")
                decision_record = {
                    **decision_payload,
                    "proposed_call": call.model_dump(mode="json"),
                }
                decisions.append(decision_record)
                self._write_supervisor_log(decision_payload)
                if camera_log_steps:
                    safe_call = redact_value(call.model_dump(mode="json"), redaction_config)
                    safe_reason = redact_value(decision.reason, redaction_config)
                    safe_args = json.dumps(safe_call["arguments"], default=str)
                    print(
                        "[supervisor:"
                        f"{supervisor_name}:{supervisor_model}] "
                        f"tool={call.tool_name} args={safe_args} "
                        f"decision={decision.decision.value} risk={decision.risk.value} "
                        f"confidence={decision.confidence:.2f} reason={safe_reason}",
                        flush=True,
                    )

                if decision.decision is Decision.ESCALATE:
                    extra_args["traceguard_stopped"] = "ESCALATE"
                    break
                if decision.decision is Decision.ALLOW:
                    approved.append(tool_call)
                    pending_calls.append(
                        call.model_copy(
                            update={
                                "tool_name": tool_call.function,
                                "arguments": dict(tool_call.args),
                            }
                        )
                    )

            extra_args.setdefault("traceguard_supervisor_decisions", []).extend(decisions)
            extra_args.setdefault("traceguard_supervisor_config", {}).update(
                {
                    "provider": supervisor_name,
                    "model": supervisor_model,
                    "confidence_threshold": supervisor_confidence_threshold,
                    "enable_rewrite": supervisor_enable_rewrite,
                    "deterministic_enabled": getattr(
                        supervisor, "deterministic_enabled", supervisor_deterministic_enabled
                    ),
                    "log_path": str(supervisor_log_path) if supervisor_log_path else None,
                }
            )
            supervisor_trace = redact_value(
                {
                    "provider": supervisor_name,
                    "model": supervisor_model,
                    "deterministic_enabled": getattr(
                        supervisor, "deterministic_enabled", supervisor_deterministic_enabled
                    ),
                    "decisions": decisions,
                },
                redaction_config,
            )
            if extra_args.get("traceguard_stopped"):
                approved = []
            if len(approved) == len(tool_calls):
                updated_messages = [
                    *messages[:-1],
                    self._assistant_message_with_supervisor_log(
                        messages[-1],
                        supervisor_trace=supervisor_trace,
                        tool_calls=approved,
                    ),
                ]
                return query, runtime, env, updated_messages, extra_args

            blocked = redact_value(
                [item for item in decisions if item["decision"] != "ALLOW"],
                redaction_config,
            )
            content = (
                "TraceGuard withheld one or more actions. Original task authority still applies."
            )
            replacement = self._assistant_message_with_supervisor_log(
                messages[-1],
                supervisor_trace=supervisor_trace,
                tool_calls=approved,
                content=[text_content_block_from_string(content)],
            )
            updated_messages = [*messages[:-1], replacement]
            if any(item["decision"] == "BLOCK" for item in decisions):
                extra_args["traceguard_block_count"] = (
                    extra_args.get("traceguard_block_count", 0) + 1
                )
                if extra_args["traceguard_block_count"] > max_block_replans:
                    extra_args.setdefault("traceguard_stopped", "BLOCK_LIMIT")
                    replacement["tool_calls"] = []
            if not approved and not extra_args.get("traceguard_stopped"):
                updated_messages.append(
                    {
                        "role": "user",
                        "content": [
                            text_content_block_from_string(
                                self._block_feedback(str(query), messages[:-1], blocked)
                            )
                        ],
                    }
                )
            return query, runtime, env, updated_messages, extra_args

        @staticmethod
        def _assistant_message_with_supervisor_log(
            message,
            *,
            supervisor_trace: dict[str, Any],
            tool_calls,
            content=None,
        ) -> dict[str, Any]:
            ordered_message = {
                "role": message.get("role", "assistant"),
                "content": message.get("content") if content is None else content,
                "traceguard_supervisor": supervisor_trace,
                "tool_calls": tool_calls,
            }
            for key, value in message.items():
                if key not in ordered_message:
                    ordered_message[key] = value
            return ordered_message

        @staticmethod
        def _observations(messages):
            return observations_from_messages(messages)

        @staticmethod
        def _tool_schemas(functions):
            schemas = {}
            for name, tool in functions.items():
                parameters = getattr(tool, "parameters", None)
                if parameters is not None and hasattr(parameters, "model_json_schema"):
                    schemas[name] = parameters.model_json_schema()
                else:
                    schemas[name] = {"type": "object"}
            return schemas

        @staticmethod
        def _block_feedback(query: str, messages, blocked) -> str:
            return (
                "TraceGuard blocked the previous action. Replan only within the original task "
                "authority. Do not repeat the blocked action or infer new approval."
            )

        @staticmethod
        def _write_supervisor_log(decision_payload: dict[str, Any]) -> None:
            if supervisor_log_path is None:
                return
            supervisor_log_path.parent.mkdir(parents=True, exist_ok=True)
            last_evaluation_log = getattr(supervisor, "last_evaluation_log", None)
            log_payload = _redacted_supervisor_log_payload(
                decision_payload,
                last_evaluation_log,
                redaction_config,
            )
            with supervisor_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(log_payload, sort_keys=True) + "\n")

    class StopOnEscalation(BasePipelineElement):
        name = "traceguard-bounded-replanning"

        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            extra_args = extra_args or {}
            if extra_args.get("traceguard_stopped"):
                return query, runtime, env, messages, extra_args
            return react_llm.query(query, runtime, env, messages, extra_args)

    pipeline = AgentPipeline(
        [
            SystemMessage(system_prompt or "ReAct AgentDojo runner with TraceGuard supervisor."),
            InitQuery(),
            react_llm,
            ToolsExecutionLoop(
                [TraceGuardAgentDojoSupervisor(), ToolsExecutor(formatter), StopOnEscalation()],
                max_iters=max_steps,
            ),
        ]
    )
    pipeline.name = f"{react_llm.name}-{supervisor_name}-supervised-local"
    return pipeline


class AgentDojoDeterministicSupervisor:
    """Deterministic-only AgentDojo guard using TraceGuard's generic LLM guardrails."""

    deterministic_enabled = True

    def __init__(self) -> None:
        self.available_tools: dict[str, dict[str, Any]] = {}
        self._guard = QwenSupervisor(
            provider=OllamaSupervisor(max_transport_retries=0),
            deterministic_enabled=True,
            enable_rewrite=False,
        )
        self.last_evaluation_log: SupervisorEvaluationLog | None = None

    def set_context(self, **kwargs) -> None:
        self._guard.set_context(**kwargs)

    def evaluate(
        self,
        user_task: str,
        call: ToolCall,
        observations: list[Observation],
    ) -> SupervisorOutput:
        self._guard.available_tools = self.available_tools
        output = self._guard._deterministic_guard(user_task, call, observations)
        self.last_evaluation_log = SupervisorEvaluationLog(
            user_goal=user_task,
            proposed_call=call.model_dump(mode="json"),
            deterministic_enabled=True,
            deterministic_decision=output.decision.value,
            provider_called=False,
            provider_response=None,
            final_decision=output.model_dump(mode="json"),
        )
        return output


def observations_from_messages(messages) -> list[Observation]:
    observations = []
    for index, message in enumerate(messages):
        if message.get("role") != "tool":
            continue
        source_id = str(message.get("tool_call_id") or f"tool-message-{index}")
        observations.append(
            Observation(
                content=_text_content(message.get("content")),
                source_type="agentdojo_tool",
                source_id=source_id,
                observation_id=str(uuid5(NAMESPACE_URL, source_id)),
                trust=TrustLabel.UNTRUSTED_TOOL,
                may_contain_instructions=True,
            )
        )
    return observations


def _executed_calls(messages) -> list[ToolCall]:
    completed_ids = {
        str(item["tool_call_id"])
        for item in messages
        if item.get("role") == "tool" and item.get("tool_call_id") and not item.get("error")
    }
    calls = []
    for index, message in enumerate(messages):
        if message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or []:
            if str(getattr(call, "id", None)) in completed_ids:
                calls.append(
                    ToolCall(
                        task_id="agentdojo",
                        step_id=index,
                        tool_name=call.function,
                        arguments=dict(call.args),
                        call_id=str(getattr(call, "id", index)),
                    )
                )
    return calls


def _text_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if content is None:
        return ""
    if isinstance(content, Sequence):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, Mapping):
                parts.append(str(item.get("content", item)))
            else:
                parts.append(str(item))
        return "\n\n".join(parts)
    return str(content)
