from traceguard.validation.metrics import paired_outcome_delta


def test_paired_uncertainty_resamples_tasks_instead_of_repeated_seeds():
    result = paired_outcome_delta(
        [0, 0, 0, 0], [1, 1, 1, 0], clusters=["task-a", "task-a", "task-a", "task-b"]
    )
    assert result["n"] == 4 and result["n_clusters"] == 2
    assert result["mean_delta"] == 0.5
