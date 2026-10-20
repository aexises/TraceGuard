import pytest

from traceguard.integrations.gateway import SupervisionGateway
from traceguard.supervisor.contracts import SupervisorResponse
from traceguard.supervisor.llm import QwenSupervisor
from traceguard.types import Decision, TaskAuthority, ToolCall

SCHEMAS = {
    "send_email": {
        "type": "object",
        "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
        "required": ["to", "body"],
        "additionalProperties": False,
    }
}


def scope():
    return TaskAuthority(
        enforcement_mode="strict",
        allowed_tools=["send_email"],
        argument_values={"send_email": {"to": "alice@example.test"}},
        generated_fields={"send_email": ["body"]},
    )


class PermissiveProvider:
    def evaluate(self, _):
        return SupervisorResponse(
            decision="ALLOW",
            risk_level="LOW",
            goal_relevance="RELEVANT",
            necessity="NECESSARY",
            confidence=1,
            reason="Permissive fake model",
        )


@pytest.mark.parametrize("mode", ["deterministic", "llm", "deterministic_llm"])
@pytest.mark.parametrize(
    "recipient,expected",
    [("alice@example.test", Decision.ALLOW), ("other@example.test", Decision.BLOCK)],
)
def test_all_strict_gateway_modes_enforce_grant_even_with_guard_disabled(mode, recipient, expected):
    gateway = SupervisionGateway(
        mode=mode,
        available_tools=SCHEMAS,
        task_authority=scope(),
        supervisor=None
        if mode == "deterministic"
        else QwenSupervisor(
            provider=PermissiveProvider(),
            deterministic_enabled=False,
        ),
    )
    _, result = gateway.evaluate(
        task_id="task",
        step_id=0,
        user_goal="Send",
        tool_name="send_email",
        arguments={"to": recipient, "body": "Safe text"},
        observations=[],
    )
    assert result.decision is expected


def test_strict_scope_cannot_select_disabled_gateway():
    with pytest.raises(ValueError, match="disable"):
        SupervisionGateway(mode="none", available_tools=SCHEMAS, task_authority=scope())


def test_standalone_llm_supervisor_cannot_skip_explicit_strict_grant():
    supervisor = QwenSupervisor(
        provider=PermissiveProvider(),
        deterministic_enabled=False,
        available_tools=SCHEMAS,
    )
    supervisor.set_context(previous_calls=[], task_authority=scope())
    call = ToolCall(
        task_id="task",
        step_id=0,
        tool_name="send_email",
        arguments={"to": "other@example.test", "body": "Safe text"},
    )
    assert supervisor.evaluate("Send", call, []).decision is Decision.BLOCK
