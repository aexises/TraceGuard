import hashlib

import pytest

from benchmarks.security_evaluation import analyze, freeze


def fixture(tmp_path):
    envelope = freeze(
        {
            "dataset": "synthetic-test-only",
            "dataset_revision": "a" * 40,
            "arm_revisions": {"baseline": "a" * 40, "treatment": "b" * 40},
            "baseline": "baseline",
            "agent_model": "fake-test-model",
            "model_settings_digest": "a" * 64,
            "executor_contract_digest": "b" * 64,
            "evaluator_revision": "c" * 40,
            "tasks": {"task": "held-out-family"},
            "development_families": ["dev-family"],
            "seeds": [1],
            "adaptive_query_budget": 4,
            "max_tool_calls": 8,
            "max_model_tokens": 1000,
        }
    )
    (tmp_path / "trace.json").write_text('{"scope":"synthetic aggregation test"}')
    digest = hashlib.sha256((tmp_path / "trace.json").read_bytes()).hexdigest()
    rows = [
        {
            "arm": arm,
            "task": "task",
            "family": "held-out-family",
            "seed": 1,
            "protocol_digest": envelope["sha256"],
            "source_revision": revision,
            "model_settings_digest": "a" * 64,
            "executor_contract_digest": "b" * 64,
            "evaluator_revision": "c" * 40,
            "utility": True,
            "prohibited_effect": False,
            "protected_data_released": False,
            "execution_unknown": arm == "baseline",
            "escalated": False,
            "adaptive_queries": 4,
            "tool_calls": 2,
            "model_tokens": 100,
            "latency_ms": 100,
            "cost_usd": 0,
            "trace_path": "trace.json",
            "trace_sha256": digest,
            "effect_evidence_path": "trace.json",
            "effect_evidence_sha256": digest,
        }
        for arm, revision in envelope["protocol"]["arm_revisions"].items()
    ]
    return envelope, rows


def test_matched_complete_trace_bound_outcomes_treat_unknown_as_incomplete(tmp_path):
    protocol, rows = fixture(tmp_path)
    result = analyze(protocol, rows, evidence_root=tmp_path)
    assert result["arms"]["baseline"]["secure_completion_episode_mean"] == 0
    assert result["secure_completion_family_paired_delta"]["treatment"]["mean_delta"] == 1


@pytest.mark.parametrize("failure", ["missing", "duplicate", "budget", "mismatch", "trace"])
def test_evaluation_rejects_incomplete_unmatched_or_unverifiable_runs(tmp_path, failure):
    protocol, rows = fixture(tmp_path)
    if failure == "missing":
        rows.pop()
    elif failure == "duplicate":
        rows.append(rows[0])
    elif failure == "budget":
        rows[0]["adaptive_queries"] = 5
    elif failure == "mismatch":
        rows[0]["executor_contract_digest"] = "c" * 64
    else:
        (tmp_path / "trace.json").write_text("changed")
    with pytest.raises(ValueError):
        analyze(protocol, rows, evidence_root=tmp_path)
