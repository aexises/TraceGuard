import sqlite3

import pytest
from test_ledger_lifecycle import legacy_ledger

from traceguard.ledger import ExecutionLedger, ExecutionUnknown
from traceguard.policy.authorization import output
from traceguard.security import SecuredTools
from traceguard.tools.registry import default_registry
from traceguard.types import Decision, PostRunAssessment, SandboxEvidence, TaskAuthority, ToolCall


def configured(tmp_path, disposition="BLOCK_RESULT"):
    dispatches, reviews = [], []

    class Supervisor:
        def evaluate(self, *args):
            return output(Decision.ALLOW, "fixture", "Approved command", risk="LOW")

        def reevaluate(self, *args):
            reviews.append(1)
            if disposition == "outage":
                raise ConnectionError("review provider unavailable")
            return PostRunAssessment(
                risk="HIGH", confidence=1, disposition=disposition, reason="fixture result decision"
            )

    class Sandbox:
        def execute(self, plan):
            dispatches.append(plan)
            return SandboxEvidence(
                exit_code=0, stdout="HARMLESS_WITHHELD_CANARY", profile="isolated_compute"
            )

    identity = ExecutionLedger.provision(tmp_path / "effects.db")
    command = ["python3", "-c", "print(7)"]
    scope = TaskAuthority(
        allowed_tools=["restricted_command"],
        argument_values={"restricted_command": {"command": command}},
    )

    def factory(version="fixture-v1"):
        return SecuredTools(
            default_registry(tmp_path, tmp_path / "artifacts"),
            scope,
            task_id="task",
            ledger_path=tmp_path / "effects.db",
            ledger_id=identity,
            supervisor=Supervisor(),
            sandbox=Sandbox(),
            post_run_reevaluation=True,
            result_policy_version=version,
        )

    proposed = ToolCall(
        task_id="task", step_id=0, tool_name="restricted_command", arguments={"command": command}
    )
    return factory, proposed, dispatches, reviews


@pytest.mark.parametrize(
    ("disposition", "outcome"),
    [
        ("BLOCK_RESULT", "BLOCK_RESULT"),
        ("ESCALATE", "ESCALATE"),
        ("REWRITE_AND_RETRY", "ESCALATE"),
        ("outage", "ESCALATE"),
    ],
)
def test_withheld_results_survive_restart_and_never_rerun_review_or_effect(
    tmp_path, disposition, outcome
):
    factory, call, dispatches, reviews = configured(tmp_path, disposition)
    first = factory().execute_call("Approved command", call, [])
    assert first.trace.episode_outcome == outcome and first.observation is None
    restarted = factory()
    retry = restarted.execute_call("Approved command", call, [])
    assert retry.trace.episode_outcome == outcome and retry.observation is None
    assert not retry.trace.result_released
    assert retry.trace.execution_status == "replayed"
    changed = call.model_copy(update={"call_id": "new-key"})
    assert factory().execute_call("Approved command", changed, []).observation is None
    assert len(dispatches) == len(reviews) == 1


def test_accepted_result_can_replay_but_changed_policy_requires_durable_review(tmp_path):
    factory, call, dispatches, reviews = configured(tmp_path, "ACCEPT_RESULT")
    assert factory().execute_call("Approved command", call, []).observation is not None
    replay = factory().execute_call("Approved command", call, [])
    assert replay.trace.episode_outcome == "REPLAYED"
    assert "HARMLESS_WITHHELD_CANARY" in replay.observation.content
    assert (
        factory("changed-policy-v2").execute_call("Approved command", call, []).observation is None
    )
    # Rolling back the policy version does not silently overturn required reconsideration.
    assert factory().execute_call("Approved command", call, []).observation is None
    assert len(dispatches) == len(reviews) == 1


@pytest.mark.parametrize("boundary", ["finish", "before-review-commit", "after-withhold-commit"])
def test_interrupted_result_commits_withhold_without_redispatch(tmp_path, monkeypatch, boundary):
    factory, call, dispatches, _ = configured(tmp_path)
    instance = factory()
    ledger = instance.effect_ledger
    original = ledger.decide_result

    def crash(*args, **kwargs):
        if boundary == "after-withhold-commit":
            original(*args, **kwargs)
        raise SystemExit("simulated process loss")

    monkeypatch.setattr(ledger, "finish" if boundary == "finish" else "decide_result", crash)
    with pytest.raises(SystemExit):
        instance.execute_call("Approved command", call, [])
    retried = factory().execute_call("Approved command", call, [])
    assert retried.observation is None and not retried.trace.result_released
    assert len(dispatches) == 1


@pytest.mark.parametrize("version", [1, 2])
def test_legacy_success_has_no_inferred_release_permission(tmp_path, version):
    path = tmp_path / "legacy.db"
    legacy_ledger(path)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE executions SET status='succeeded',result='PRIVATE_CANARY'")
        if version == 2:
            connection.execute(
                "CREATE TABLE ledger_metadata (singleton INTEGER, schema INTEGER, store_id TEXT)"
            )
            connection.execute("INSERT INTO ledger_metadata VALUES (1,2,'approved-domain')")
    ExecutionLedger.migrate_legacy(
        path, backup=tmp_path / "backup.db", store_id="approved-domain", workers_fenced=True
    )
    ledger = ExecutionLedger(path, expected_store_id="approved-domain")
    replay = ledger.reserve(
        scope=("tenant", "agent", "credential", "task"),
        nonce="first",
        idempotency_key="first",
        digest="first",
        effect_digest="first",
    )
    assert replay["result"] is None and replay["disposition"] == "review_required"
    with pytest.raises(ExecutionUnknown):
        ledger.decide_result("first", "accepted_for_agent", result_policy="")


def test_missing_result_bytes_are_not_a_successful_replay(tmp_path):
    factory, call, dispatches, _ = configured(tmp_path, "ACCEPT_RESULT")
    factory().execute_call("Approved command", call, [])
    with sqlite3.connect(tmp_path / "effects.db") as connection:
        connection.execute("UPDATE executions SET result=NULL")
    assert factory().execute_call("Approved command", call, []).observation is None
    assert len(dispatches) == 1
