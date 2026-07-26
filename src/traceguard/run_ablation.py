"""Unified ablation entry point for TraceGuard supervisor modes."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from benchmarks.schema import default_cases_path, load_cases
from traceguard.conclusion_ablation import (
    DEFAULT_INJECTION_TASKS,
    DEFAULT_USER_TASKS,
    PUBLIC_MODES,
    _namespace_for_react,
    build_mode_metrics,
)
from traceguard.experiments import run_experiment
from traceguard.supervisor.factory import (
    build_supervisor_bundle,
    safeguard_config_for_mode,
)


def _run_custom(args: argparse.Namespace) -> int:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_dir or Path(f"artifacts/ablations-custom-{timestamp}")
    config = safeguard_config_for_mode(args.supervisor)
    bundle = build_supervisor_bundle(
        config,
        provider=args.provider,
        supervisor_model=args.supervisor_model,
        gemini_api_key=getattr(args, "gemini_api_key", None),
        gemini_base_url=getattr(args, "gemini_base_url", None),
        timeout=args.timeout,
        max_retries=getattr(args, "supervisor_max_retries", 2),
        confidence_threshold=getattr(args, "supervisor_confidence_threshold", 0.55),
        enable_rewrite=getattr(args, "supervisor_enable_rewrite", False),
    )
    if args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "suite": "custom",
            "supervisor": args.supervisor,
            "agent_model": args.agent_model,
            "agent_provider": getattr(args, "agent_provider", "ollama"),
            "supervisor_model": args.supervisor_model,
            "provider": args.provider,
            "gemini_base_url": getattr(args, "gemini_base_url", None),
            "repetitions": getattr(args, "repetitions", 1),
            "seeds": [args.seed + index for index in range(getattr(args, "repetitions", 1))],
            "output_dir": str(output_dir),
        }
        (output_dir / "dry_run_plan.json").write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )
        print(json.dumps(payload, indent=2))
        return 0

    cases = load_cases(default_cases_path(), split="dev")
    ablations = {args.supervisor: bundle.config}
    runs = []
    total_results = 0
    for repetition in range(getattr(args, "repetitions", 1)):
        seed = args.seed + repetition
        results, report, run_dir = run_experiment(
            cases=cases,
            ablations=ablations,
            seed=seed,
            artifacts_dir=output_dir,
            supervisor_provider=args.provider,
            supervisor_model=args.supervisor_model,
            supervisor_url=args.supervisor_url,
            gemini_api_key=getattr(args, "gemini_api_key", None),
            gemini_base_url=getattr(args, "gemini_base_url", None),
            timeout=args.timeout,
            supervisor_max_retries=getattr(args, "supervisor_max_retries", 2),
            supervisor_confidence_threshold=getattr(args, "supervisor_confidence_threshold", 0.55),
            supervisor_enable_rewrite=getattr(args, "supervisor_enable_rewrite", False),
            agent_provider=getattr(args, "agent_provider", "ollama"),
            agent_model=args.agent_model,
            agent_url=getattr(args, "ollama_url", None),
        )
        total_results += len(results)
        runs.append(
            {
                "run_dir": str(run_dir),
                "seed": seed,
                "results": len(results),
                "episode_metrics": report.episode,
            }
        )
    print(
        json.dumps(
            {
                "runs": runs,
                "results": total_results,
            },
            indent=2,
        )
    )
    return 0


def _run_agentdojo(args: argparse.Namespace) -> int:
    if args.agent_provider == "scripted":
        raise ValueError("AgentDojo requires --agent-provider ollama or gemini")
    if not args.user_task:
        args.user_task = DEFAULT_USER_TASKS[:2] if args.smoke else DEFAULT_USER_TASKS
    if not args.injection_task:
        args.injection_task = DEFAULT_INJECTION_TASKS[:1] if args.smoke else DEFAULT_INJECTION_TASKS

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_dir or Path(f"artifacts/ablations-agentdojo-{timestamp}")
    clean_dir = output_dir / args.supervisor / "clean"
    attack_dir = output_dir / args.supervisor / "attack"

    if args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "suite": "agentdojo",
            "supervisor": args.supervisor,
            "agentdojo_suite": args.agentdojo_suite,
            "user_tasks": args.user_task,
            "injection_tasks": args.injection_task,
            "attack": None if args.no_attack else args.attack,
            "gemini_base_url": getattr(args, "gemini_base_url", None),
            "camera_log_steps": getattr(args, "camera_log_steps", False),
            "repetitions": args.repetitions,
            "seeds": [args.seed + index for index in range(args.repetitions)],
            "output_dir": str(output_dir),
        }
        (output_dir / "dry_run_plan.json").write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )
        print(json.dumps(payload, indent=2))
        return 0

    from react_agentdojo.agentdojo_react_benchmark import run_benchmark

    seeds = [args.seed + index for index in range(args.repetitions)]
    for repetition, seed in enumerate(seeds):
        run_name = f"repetition_{repetition:03d}_seed_{seed}"
        run_benchmark(
            _namespace_for_react(
                args,
                mode=args.supervisor,
                logdir=clean_dir / run_name,
                attack=False,
                seed=seed,
            )
        )
    if args.no_attack:
        print(json.dumps({"logdir": str(clean_dir)}, indent=2))
        return 0

    for repetition, seed in enumerate(seeds):
        run_name = f"repetition_{repetition:03d}_seed_{seed}"
        run_benchmark(
            _namespace_for_react(
                args,
                mode=args.supervisor,
                logdir=attack_dir / run_name,
                attack=True,
                seed=seed,
            )
        )
    metrics = build_mode_metrics(
        mode=args.supervisor,
        clean_logdir=clean_dir,
        attack_logdir=attack_dir,
    )
    metrics.update(
        {
            "repetitions": args.repetitions,
            "seed_start": args.seed,
            "seeds": seeds,
        }
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=["custom", "agentdojo"], required=True)
    parser.add_argument("--supervisor", choices=PUBLIC_MODES, required=True)
    parser.add_argument("--agent-model", default="qwen3:4b")
    parser.add_argument(
        "--agent-provider",
        choices=["scripted", "ollama", "gemini"],
        default="ollama",
    )
    parser.add_argument("--supervisor-model", default="qwen3:4b")
    parser.add_argument("--provider", choices=["ollama", "gemini", "heuristic"], default="ollama")
    parser.add_argument("--agentdojo-suite", default="workspace")
    parser.add_argument("--user-task", action="append", default=[])
    parser.add_argument("--injection-task", action="append", default=[])
    parser.add_argument("--attack", default="tool_knowledge")
    parser.add_argument("--no-attack", action="store_true")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--force-rerun", action="store_true")
    parser.add_argument("--dangerously-follow-tool-instructions", action="store_true")
    parser.add_argument("--disable-agent-action-guards", action="store_true")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--supervisor-url", default="http://127.0.0.1:11434")
    parser.add_argument("--gemini-api-key", default=None)
    parser.add_argument("--gemini-base-url", default=None)
    parser.add_argument("--max-steps", type=int, default=10)
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument("--format-retries", type=int, default=2)
    parser.add_argument("--repeat-retries", type=int, default=3)
    parser.add_argument("--tool-output-format", choices=["yaml", "json"], default=None)
    parser.add_argument(
        "--camera-log-steps",
        action="store_true",
        help="print redacted agent outputs and supervisor decisions live for recording",
    )
    parser.add_argument("--supervisor-max-retries", type=int, default=2)
    parser.add_argument("--supervisor-confidence-threshold", type=float, default=0.55)
    parser.add_argument("--supervisor-enable-rewrite", action="store_true")
    parser.add_argument("--supervisor-redaction-config", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.repetitions < 1:
        parser.error("--repetitions must be at least 1")
    if args.suite == "custom":
        return _run_custom(args)
    return _run_agentdojo(args)


if __name__ == "__main__":
    raise SystemExit(main())
