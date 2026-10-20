"""The product cannot select the removed unguarded experiment modes."""

import pytest
from pydantic import ValidationError

from traceguard._enforcement import GuardedExecution
from traceguard.integrations.gateway import SupervisionGateway
from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.tools.registry import default_registry
from traceguard.types import EnforcementConfig, TaskAuthority


def test_execution_configuration_cannot_disable_deterministic_authority():
    with pytest.raises(ValidationError):
        EnforcementConfig(deterministic_policy=False)


@pytest.mark.parametrize("authority", [None, TaskAuthority(allowed_tools=[])])
def test_embedded_and_gateway_boundaries_reject_missing_strict_scope(tmp_path, authority):
    tools = default_registry(tmp_path, tmp_path / "artifacts")
    with pytest.raises(ValueError, match="strict authority"):
        GuardedExecution(
            tools,
            EnforcementConfig(),
            policy=DeterministicPolicy(load_default_policy()),
            task_authority=authority,
            bound_task_id="approved-task",
        )
    with pytest.raises(ValueError, match="strict authority"):
        SupervisionGateway(
            mode="deterministic", available_tools=tools.schemas(), task_authority=authority
        )


def test_private_execution_cannot_create_an_unbound_task_context(tmp_path):
    with pytest.raises(ValueError, match="bound task"):
        GuardedExecution(
            default_registry(tmp_path, tmp_path / "artifacts"),
            EnforcementConfig(),
            policy=DeterministicPolicy(load_default_policy()),
            task_authority=TaskAuthority(enforcement_mode="strict", allowed_tools=[]),
        )
