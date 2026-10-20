from traceguard.supervisor.base import merge_outputs
from traceguard.types import (
    Decision,
    GoalNecessity,
    GoalRelevance,
    RiskLevel,
    SupervisorOutput,
    ToolCall,
)


def output(decision):
    return SupervisorOutput(
        decision=decision,
        risk=RiskLevel.LOW,
        confidence=1,
        policy_violation=False,
        goal_relevance=GoalRelevance.STRONG,
        goal_necessity=GoalNecessity.HELPFUL,
        reason="test",
        rewritten_call=ToolCall(task_id="t", step_id=0, tool_name="calculator")
        if decision is Decision.REWRITE
        else None,
    )


def test_decision_precedence():
    assert (
        merge_outputs(
            [output(Decision.ALLOW), output(Decision.REWRITE), output(Decision.ESCALATE)]
        ).decision
        is Decision.ESCALATE
    )
