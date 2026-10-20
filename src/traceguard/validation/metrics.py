"""Paired, task-clustered uncertainty for externally supplied security outcomes."""

import math
import random
from collections import defaultdict
from collections.abc import Sequence


def bootstrap_ci(
    values: Sequence[float],
    *,
    n_boot: int = 1000,
    alpha: float = 0.05,
    seed: int = 0,
) -> dict[str, float | None]:
    if not values:
        return {"mean": None, "low": None, "high": None}
    rng = random.Random(seed)
    samples = []
    data = list(values)
    for _ in range(n_boot):
        draw = [data[rng.randrange(len(data))] for _ in range(len(data))]
        samples.append(sum(draw) / len(draw))
    samples.sort()
    low_idx = int(math.floor((alpha / 2) * (n_boot - 1)))
    high_idx = int(math.ceil((1 - alpha / 2) * (n_boot - 1)))
    return {
        "mean": sum(data) / len(data),
        "low": samples[low_idx],
        "high": samples[high_idx],
    }


def paired_outcome_delta(
    baseline: Sequence[float],
    treatment: Sequence[float],
    *,
    clusters: Sequence[str] | None = None,
) -> dict[str, float | None]:
    if len(baseline) != len(treatment):
        raise ValueError("paired comparisons require equal-length series")
    if not baseline:
        return {"mean_delta": None, "n": 0}
    deltas = [t - b for b, t in zip(baseline, treatment, strict=True)]
    if clusters is not None:
        if len(clusters) != len(deltas):
            raise ValueError("cluster IDs must align with paired outcomes")
        grouped = defaultdict(list)
        for key, delta in zip(clusters, deltas, strict=True):
            grouped[key].append(delta)
        values = [sum(items) / len(items) for items in grouped.values()]
        return {
            "mean_delta": sum(values) / len(values),
            "n": len(deltas),
            "n_clusters": len(values),
            **bootstrap_ci(values),
        }
    return {"mean_delta": sum(deltas) / len(deltas), "n": len(deltas), **bootstrap_ci(deltas)}
