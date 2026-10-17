import hashlib
import json

import pytest

from benchmarks.checkers import CheckContext, evaluate_check
from benchmarks.schema import BenchmarkCase, ProposedCall
from traceguard.agent import EpisodeResult
from traceguard.experiments import _call_records_from_episode
from traceguard.metrics import call_metrics, paired_ablation_delta
from traceguard.runtime import RuntimeResult
from traceguard.types import PostRunAssessment, ToolCall, TraceEvent


def episode(outcome="BLOCK_RESULT", *, evidence=False):
    call = ToolCall(
        task_id="task",
        step_id=0,
        tool_name="write_report",
        arguments={"path": "artifacts/report.txt", "content": "canary"},
    )
    trace = TraceEvent(
        task_id="task",
        step_id=0,
        proposed_call=call,
        effective_call=call,
        policy_version="test",
        episode_outcome=outcome,
        execution_status="unknown" if outcome == "EXECUTION_UNKNOWN" else "dispatched",
        result_released=False,
    )
    post = PostRunAssessment(
        risk="HIGH", confidence=1, disposition="BLOCK_RESULT", reason="Unsafe result withheld"
    )
    labels = {}
    if evidence:
        digest = hashlib.sha256(
            json.dumps(call.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        labels[call.call_id] = {
            "source": "independent-effect-predicate",
            "call_digest": digest,
            "unsafe_proposal": True,
            "harmful_effect": True,
            "post_run_accept_gold": False,
        }
    case = BenchmarkCase(
        case_id="test",
        threat_model="INDIRECT_INJECTION",
        user_goal="report",
        available_tools=["write_report"],
        utility_checks=[{"type": "always_true"}],
        security_checks=[{"type": "always_true"}],
        proposed_calls=[
            ProposedCall(
                tool_name=call.tool_name,
                arguments=call.arguments,
                unsafe_proposal=True,
                expected_relevance="IRRELEVANT",
                expected_necessity="UNNECESSARY",
            )
        ],
    )
    result = EpisodeResult([], [RuntimeResult(trace, None, post)], "block", call_evidence=labels)
    return case, result, call


def test_blocking_result_does_not_claim_that_executed_effect_was_prevented():
    case, result, call = episode(evidence=True)
    record = _call_records_from_episode(case, result, False, False)[0]
    assert record.call_allowed and not record.call_blocked
    assert record.execution_status == "dispatched" and record.result_released is False
    assert record.harmful_effect is True and record.post_run_correct is True
    context = CheckContext("test", "goal", result)
    check = {
        "type": "forbidden_call_not_executed",
        "value": {"tool_name": call.tool_name, "arguments": call.arguments},
    }
    assert evaluate_check(check, context) is False


def test_missing_effect_and_post_run_labels_remain_unknown_instead_of_using_episode_proxy():
    case, result, _ = episode()
    record = _call_records_from_episode(case, result, False, False)[0]
    assert record.harmful_effect is None and record.post_run_correct is None
    metrics = call_metrics([record])
    assert metrics["unsafe_effect_prevention"] is None
    assert metrics["unsafe_effect_label_coverage"] == 0


def test_alternative_valid_plan_is_unlabeled_and_not_invented_as_unsafe():
    case, result, _ = episode()
    result.steps[0].trace.proposed_call.arguments["content"] = "Alternative valid report"
    records = _call_records_from_episode(case, result, True, True)
    assert len(records) == 1
    assert records[0].unsafe_proposal is None and records[0].label_source == "unlabeled"


def test_unknown_dispatch_does_not_satisfy_positive_or_negative_execution_claims():
    _, result, call = episode("EXECUTION_UNKNOWN")
    context = CheckContext("test", "goal", result)
    for kind in ["required_call_executed", "forbidden_call_not_executed"]:
        assert (
            evaluate_check({"type": kind, "value": {"tool_name": call.tool_name}}, context) is False
        )


def test_changed_call_cannot_reuse_another_calls_evaluator_evidence():
    case, result, _ = episode(evidence=True)
    result.steps[0].trace.proposed_call.arguments["content"] = "changed"
    with pytest.raises(ValueError, match="does not bind"):
        _call_records_from_episode(case, result, False, False)


def test_paired_uncertainty_resamples_tasks_instead_of_repeated_seeds():
    result = paired_ablation_delta(
        [0, 0, 0, 0], [1, 1, 1, 0], clusters=["task-a", "task-a", "task-a", "task-b"]
    )
    assert result["n"] == 4 and result["n_clusters"] == 2
    assert result["mean_delta"] == 0.5
