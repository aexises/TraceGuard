import pytest

from traceguard.runtime import TraceGuardRuntime
from traceguard.supervisor.base import enforce_allow_invariants
from traceguard.tools.registry import default_registry
from traceguard.types import (
    Decision,
    ExecutionTarget,
    GoalNecessity,
    GoalRelevance,
    RiskLevel,
    SafeguardConfig,
    SupervisorOutput,
    ToolCall,
)


def allow(**updates):
    return SupervisorOutput(
        **{
            "decision": Decision.ALLOW,
            "risk": RiskLevel.LOW,
            "confidence": 1,
            "policy_violation": False,
            "goal_relevance": GoalRelevance.UNCERTAIN,
            "goal_necessity": GoalNecessity.UNCERTAIN,
            "reason": "test",
            **updates,
        }
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"risk": RiskLevel.HIGH},
        {"risk": RiskLevel.CRITICAL},
        {"policy_violation": True},
        {"goal_relevance": GoalRelevance.IRRELEVANT},
        {"goal_necessity": GoalNecessity.UNNECESSARY},
    ],
)
def test_inconsistent_allow_is_never_executable(updates):
    assert enforce_allow_invariants(allow(**updates)).decision is Decision.ESCALATE


def test_simulated_write_does_not_invoke_handler_or_record_execution(tmp_path):
    class Supervisor:
        def evaluate(self, *_):
            return allow(execution_target=ExecutionTarget.SIMULATED)

    tools = default_registry(tmp_path, tmp_path / "artifacts")

    def forbidden_handler(_):
        raise AssertionError("simulation invoked a real handler")

    tools.get("write_report").handler = forbidden_handler
    runtime = TraceGuardRuntime(
        tools, SafeguardConfig(llm_supervisor=True), supervisor=Supervisor()
    )
    result = runtime.execute_call(
        "Write",
        ToolCall(
            task_id="t",
            step_id=0,
            tool_name="write_report",
            arguments={"path": "artifacts/report.txt", "content": "canary"},
        ),
        [],
    )
    assert result.trace.episode_outcome == "SIMULATED"
    assert not (tmp_path / "artifacts/report.txt").exists()
    assert runtime.executed_calls == {}


def test_critical_container_allow_never_invokes_sandbox(tmp_path):
    class Supervisor:
        def evaluate(self, *_):
            return allow(
                risk=RiskLevel.CRITICAL,
                execution_target=ExecutionTarget.CONTAINER,
                container_profile="isolated_compute",
            )

    class Sandbox:
        def execute(self, _):
            raise AssertionError("critical risk reached execution")

    runtime = TraceGuardRuntime(
        default_registry(tmp_path, tmp_path / "artifacts"),
        SafeguardConfig(llm_supervisor=True),
        supervisor=Supervisor(),
        sandbox=Sandbox(),
    )
    result = runtime.execute_call(
        "Run",
        ToolCall(
            task_id="t",
            step_id=0,
            tool_name="restricted_command",
            arguments={"command": ["python", "-V"]},
        ),
        [],
    )
    assert result.trace.episode_outcome == "ESCALATE"
    assert runtime.executed_calls == {}
