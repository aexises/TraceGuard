import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from traceguard.types import (
    CONTRACT_VERSION,
    Decision,
    ExecutionTarget,
    GoalNecessity,
    GoalRelevance,
    RiskLevel,
    SupervisorOutput,
)


def test_types_v4_contract_and_shared_fixtures_are_versioned():
    assert CONTRACT_VERSION == "types-v4"
    fixtures = json.loads(Path("tests/fixtures/contracts.json").read_text(encoding="utf-8"))
    assert {fixture["fixture"] for fixture in fixtures} == {
        "benign_call",
        "direct_attack",
        "indirect_injection",
        "policy_violation",
        "rewrite",
        "container_route",
    }


def test_rewrite_requires_rewritten_call():
    with pytest.raises(ValidationError):
        SupervisorOutput(
            decision=Decision.REWRITE,
            risk=RiskLevel.LOW,
            confidence=1,
            policy_violation=False,
            goal_relevance=GoalRelevance.STRONG,
            goal_necessity=GoalNecessity.HELPFUL,
            reason="rewrite",
        )


def test_container_target_requires_profile():
    with pytest.raises(ValidationError):
        SupervisorOutput(
            decision=Decision.ALLOW,
            risk=RiskLevel.MEDIUM,
            confidence=1,
            policy_violation=False,
            goal_relevance=GoalRelevance.STRONG,
            goal_necessity=GoalNecessity.HELPFUL,
            reason="contain",
            execution_target=ExecutionTarget.CONTAINER,
        )
