import argparse
from pathlib import Path
from types import SimpleNamespace

from traceguard.run_ablation import _run_agentdojo, _run_custom, build_parser


def test_custom_ablation_forwards_requested_supervisor_provider(monkeypatch, tmp_path):
    captured = {"run_experiment": []}

    def fake_load_cases(path, *, split):
        captured["load_cases"] = {"path": path, "split": split}
        return []

    def fake_run_experiment(**kwargs):
        captured["run_experiment"].append(kwargs)
        return [], SimpleNamespace(episode={}), tmp_path / "run"

    monkeypatch.setattr("traceguard.run_ablation.load_cases", fake_load_cases)
    monkeypatch.setattr("traceguard.run_ablation.run_experiment", fake_run_experiment)

    args = argparse.Namespace(
        output_dir=tmp_path,
        supervisor="llm",
        provider="ollama",
        supervisor_model="qwen3:4b",
        supervisor_url="http://127.0.0.1:11434",
        timeout=37.0,
        seed=11,
        repetitions=2,
        agent_model="qwen3:4b",
        gemini_api_key="test-key",
        gemini_base_url="https://open.blackroute.space/v1",
        dry_run=False,
    )

    assert _run_custom(args) == 0

    assert [item["seed"] for item in captured["run_experiment"]] == [11, 12]
    run_kwargs = captured["run_experiment"][0]
    assert run_kwargs["supervisor_provider"] == "ollama"
    assert run_kwargs["supervisor_model"] == "qwen3:4b"
    assert run_kwargs["supervisor_url"] == "http://127.0.0.1:11434"
    assert run_kwargs["gemini_api_key"] == "test-key"
    assert run_kwargs["gemini_base_url"] == "https://open.blackroute.space/v1"
    assert run_kwargs["timeout"] == 37.0
    assert run_kwargs["seed"] == 11
    assert run_kwargs["artifacts_dir"] == Path(tmp_path)


def test_agentdojo_ablation_runs_each_requested_seed(monkeypatch, tmp_path):
    calls = []

    def fake_run_benchmark(args):
        calls.append(args)
        return SimpleNamespace()

    monkeypatch.setattr(
        "react_agentdojo.agentdojo_react_benchmark.run_benchmark",
        fake_run_benchmark,
    )
    args = build_parser().parse_args(
        [
            "--suite",
            "agentdojo",
            "--supervisor",
            "none",
            "--no-attack",
            "--repetitions",
            "3",
            "--seed",
            "7",
            "--output-dir",
            str(tmp_path),
        ]
    )

    assert _run_agentdojo(args) == 0

    assert [call.seed for call in calls] == [7, 8, 9]
    assert [call.logdir.name for call in calls] == [
        "repetition_000_seed_7",
        "repetition_001_seed_8",
        "repetition_002_seed_9",
    ]
