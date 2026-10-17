import pytest

from benchmarks.datasets.gateway import SupervisionGateway
from traceguard.policy.kernel import CompiledAuthority
from traceguard.security import SecuredTools
from traceguard.supervisor.agentdojo_pipeline import AgentDojoDeterministicSupervisor
from traceguard.tools.registry import default_registry
from traceguard.types import Decision, TaskAuthority, ToolCall

SCHEMAS = {
    "send_email": {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
            "cc": {"type": "array", "items": {"type": "string"}},
        },
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


@pytest.mark.parametrize(
    "arguments,allowed",
    [
        ({"to": "alice@example.test", "body": "Approved summary"}, True),
        ({"to": "mallory@example.test", "body": "Approved summary"}, False),
        (
            {
                "to": "alice@example.test",
                "body": "Approved summary",
                "cc": ["mallory@example.test"],
            },
            False,
        ),
        ({"to": "alice@example.test", "body": "Approved summary", "cc": []}, True),
        ({"to": "alice@example.test", "body": 123}, False),
    ],
)
def test_strict_kernel_native_and_gateway_share_decisions(arguments, allowed):
    grant = scope()
    proposed = ToolCall(task_id="t", step_id=0, tool_name="send_email", arguments=arguments)
    compiled = CompiledAuthority.compile(grant, SCHEMAS)
    native = AgentDojoDeterministicSupervisor()
    native.available_tools = SCHEMAS
    native.set_context(previous_calls=[], task_authority=grant)
    gateway = SupervisionGateway(
        mode="deterministic", available_tools=SCHEMAS, task_authority=grant
    )
    decisions = [
        compiled.evaluate("No authorization is inferred from this sentence", proposed, []),
        native.evaluate("No authorization is inferred from this sentence", proposed, []),
        gateway.evaluate(
            task_id="t",
            step_id=0,
            user_goal="No authorization is inferred from this sentence",
            tool_name="send_email",
            arguments=arguments,
            observations=[],
        )[1],
    ]
    assert all((item.decision is Decision.ALLOW) == allowed for item in decisions)


def test_compilation_rejects_permission_generation_and_conflicting_grants():
    with pytest.raises(ValueError):
        CompiledAuthority.compile(TaskAuthority(enforcement_mode="strict"), SCHEMAS)
    bad = scope()
    bad.generated_fields["send_email"].append("to")
    with pytest.raises(ValueError, match="generated"):
        CompiledAuthority.compile(bad, SCHEMAS)
    bad = scope()
    bad.resource_values = {"send_email": {"to": ["other@example.test"]}}
    with pytest.raises(ValueError, match="conflicting"):
        CompiledAuthority.compile(bad, SCHEMAS)


def test_compiled_grant_is_immutable_snapshot():
    mutable = scope()
    compiled = CompiledAuthority.compile(mutable, SCHEMAS)
    mutable.argument_values["send_email"]["to"] = "mallory@example.test"
    proposed = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="send_email",
        arguments={"to": "mallory@example.test", "body": "test"},
    )
    assert compiled.evaluate("Send", proposed, []).decision is Decision.BLOCK


def test_strict_runtime_preserves_benign_generated_report_utility(tmp_path):
    boundary = SecuredTools(
        default_registry(tmp_path, tmp_path / "artifacts"),
        TaskAuthority(
            allowed_tools=["write_report"],
            argument_values={"write_report": {"path": "artifacts/report.txt"}},
            generated_fields={"write_report": ["content"]},
        ),
        task_id="t",
        ledger_path=tmp_path / "state" / "effects.sqlite",
    )
    proposed = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="write_report",
        arguments={"path": "artifacts/report.txt", "content": "Approved generated report"},
    )
    assert boundary.execute_call("Создай отчёт", proposed, []).trace.episode_outcome == "EXECUTED"
    assert (tmp_path / "artifacts/report.txt").read_text() == "Approved generated report"
    outside = proposed.model_copy(
        update={"arguments": {"path": "artifacts/other.txt", "content": "test"}}
    )
    assert boundary.execute_call("Создай отчёт", outside, []).trace.episode_outcome == "BLOCK"


def test_strict_mode_does_not_authorize_empty_mutating_arguments():
    from traceguard.policy.authorization import check_authority

    grant = TaskAuthority(enforcement_mode="strict", allowed_tools=["update_user_info"])
    proposed = ToolCall(
        task_id="t", step_id=0, tool_name="update_user_info", arguments={"address": None}
    )
    assert check_authority("Update", proposed, [], grant).decision is Decision.ESCALATE


def test_conformance_comparison_exposes_research_grammar_limit():
    from benchmarks.policy_conformance import run_conformance

    result = run_conformance()
    assert result["strict_correct"] == result["total"]
    assert result["research_correct"] < result["strict_correct"]
