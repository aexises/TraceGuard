from concurrent.futures import ThreadPoolExecutor

import pytest

from traceguard.security import SecuredTools
from traceguard.tools.registry import default_registry
from traceguard.types import TaskAuthority, ToolCall


def setup(tmp_path, *, failing=False, repeatable=False):
    registry = default_registry(tmp_path, tmp_path / "artifacts")
    effects = []
    original = registry.get("write_report").handler

    def handler(args):
        effects.append(original(args))
        if failing:
            raise OSError("HARMLESS_CANARY: effect happened before connection failed")
        return effects[-1]

    registry.get("write_report").handler = handler
    scope = TaskAuthority(
        allowed_tools=["write_report"],
        repeatable_tools=["write_report"] if repeatable else [],
        argument_values={"write_report": {"path": "artifacts/report.txt"}},
        generated_fields={"write_report": ["content"]},
    )

    def factory():
        return SecuredTools(
            registry, scope, task_id="task", ledger_path=tmp_path / "state/effects.db"
        )

    proposed = ToolCall(
        task_id="task",
        step_id=0,
        tool_name="write_report",
        arguments={"path": "artifacts/report.txt", "content": "Safe report"},
    )
    return factory, proposed, effects


@pytest.mark.parametrize("repeatable", [False, True])
def test_post_effect_failure_cannot_retry_even_after_restart_or_new_key(tmp_path, repeatable):
    factory, proposed, effects = setup(tmp_path, failing=True, repeatable=repeatable)
    assert (
        factory().execute_call("Write", proposed, []).trace.episode_outcome == "EXECUTION_UNKNOWN"
    )
    new = proposed.model_copy(update={"call_id": "fresh-key"})
    assert factory().execute_call("Write", new, []).trace.episode_outcome == "ESCALATE"
    assert len(effects) == 1


def test_successful_receipt_survives_restart_and_wrong_task_cannot_reset_scope(tmp_path):
    factory, proposed, effects = setup(tmp_path)
    assert factory().execute_call("Write", proposed, []).trace.episode_outcome == "EXECUTED"
    assert factory().execute_call("Write", proposed, []).trace.episode_outcome == "REPLAYED"
    other = proposed.model_copy(update={"task_id": "new-task", "call_id": "fresh-key"})
    assert factory().execute_call("Write", other, []).trace.episode_outcome == "BLOCK"
    assert len(effects) == 1


def test_two_runtime_instances_share_atomic_effect_reservation(tmp_path):
    factory, proposed, effects = setup(tmp_path)
    instances = [factory(), factory()]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(lambda runtime: runtime.execute_call("Write", proposed, []), instances)
        )
    assert len(effects) == 1
    assert any(result.trace.episode_outcome == "EXECUTED" for result in outcomes)


def test_embedded_mutations_require_explicit_private_ledger(tmp_path):
    with pytest.raises(ValueError, match="ledger_path"):
        SecuredTools(
            default_registry(tmp_path, tmp_path / "artifacts"),
            TaskAuthority(allowed_tools=["write_report"]),
            task_id="task",
        )
