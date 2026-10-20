"""Deterministic supervision without an agent or experiment runner."""

from typing import Any

from traceguard.supervisor.contracts import SupervisorEvaluationLog
from traceguard.supervisor.llm import OllamaSupervisor, QwenSupervisor
from traceguard.types import Observation, SupervisorOutput, ToolCall


class DeterministicSupervisor:
    """Deterministic pre-call guard; never invokes a model."""

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
