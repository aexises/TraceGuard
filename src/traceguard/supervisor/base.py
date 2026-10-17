"""Supervisor interface and deterministic combination semantics."""

from __future__ import annotations

from typing import Protocol

from traceguard.types import (
    Decision,
    GoalNecessity,
    GoalRelevance,
    Observation,
    RiskLevel,
    SandboxEvidence,
    SupervisorOutput,
    ToolCall,
)


class Supervisor(Protocol):
    def evaluate(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> SupervisorOutput: ...

    def reevaluate(self, user_task: str, call: ToolCall, evidence: SandboxEvidence): ...


_PRECEDENCE = {"ALLOW": 0, "REWRITE": 1, "ESCALATE": 2, "BLOCK": 3}
_RISK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def enforce_allow_invariants(output: SupervisorOutput) -> SupervisorOutput:
    if output.decision is Decision.ALLOW and (
        output.risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        or output.policy_violation
        or output.goal_relevance is GoalRelevance.IRRELEVANT
        or output.goal_necessity is GoalNecessity.UNNECESSARY
    ):
        return output.model_copy(
            update={
                "decision": Decision.ESCALATE,
                "reason": "Inconsistent ALLOW requires review before execution.",
                "execution_target": None,
                "container_profile": None,
                "matched_rules": [*output.matched_rules, "execution-allow-invariant"],
            }
        )
    return output


def merge_outputs(outputs: list[SupervisorOutput]) -> SupervisorOutput | None:
    if not outputs:
        return None
    winner = max(
        enumerate(outputs), key=lambda item: (_PRECEDENCE[item[1].decision.value], item[0])
    )[1]
    winner = winner.model_copy(
        update={"risk": max(outputs, key=lambda item: _RISK[item.risk.value]).risk}
    )
    container_outputs = [
        output for output in outputs if output.execution_target and output.container_profile
    ]
    if container_outputs and winner.decision.value not in {"BLOCK", "ESCALATE"}:
        strictest = max(container_outputs, key=lambda output: _RISK[output.risk.value])
        return enforce_allow_invariants(
            winner.model_copy(
                update={
                    "execution_target": strictest.execution_target,
                    "container_profile": strictest.container_profile,
                }
            )
        )
    return enforce_allow_invariants(winner)
