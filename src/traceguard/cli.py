from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from benchmarks.agentdojo_adapter import (
    load_selection,
    validate_selection,
    verify_agentdojo_installation,
)
from benchmarks.datasets.models import AdapterRunRequest
from benchmarks.datasets.registry import default_dataset_registry
from benchmarks.datasets.reporting import separated_dataset_report
from benchmarks.schema import default_cases_path, load_cases
from traceguard.agent import ReActRunner, ScriptedAgent
from traceguard.experiments import (
    default_ablations_path,
    load_ablations,
    regenerate_analysis_from_traces,
    run_experiment,
)
from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.runtime import TraceGuardRuntime
from traceguard.sandbox.config import default_sandbox_configuration_path
from traceguard.sandbox.runner import ContainerRunner, SandboxUnavailable
from traceguard.supervisor.heuristic import HeuristicSupervisor
from traceguard.supervisor.redaction import redact_value
from traceguard.tools.registry import default_registry
from traceguard.types import ExecutionPlan, ExecutionTarget, SafeguardConfig, ToolCall


def _dataset_registry(args: argparse.Namespace):
    return default_dataset_registry(cache_root=args.cache_root)


def _environment_lock_digest(native_environment: str | None) -> str:
    project_root = Path(__file__).resolve().parents[2]
    lock_path = project_root / "uv.lock"
    if native_environment:
        environment_name = native_environment.removeprefix(".venv-")
        lock_path = project_root / "benchmarks" / "environments" / environment_name / "uv.lock"
    if not lock_path.is_file():
        raise ValueError(f"environment lock is missing: {lock_path}")
    return hashlib.sha256(lock_path.read_bytes()).hexdigest()


def _dataset_command(args: argparse.Namespace) -> int:
    registry = _dataset_registry(args)
    if args.dataset_command == "list":
        print(json.dumps(registry.describe(), indent=2))
        return 0
    if args.dataset_command == "fetch":
        print(json.dumps(registry.fetch(args.name), indent=2))
        return 0
    if args.dataset_command == "verify":
        print(
            json.dumps(
                registry.verify(args.name, fixture_only=args.fixture_only),
                indent=2,
            )
        )
        return 0
    return 2


def _benchmark_request(
    args: argparse.Namespace,
    dataset: str,
) -> AdapterRunRequest:
    registry = _dataset_registry(args)
    manifest = registry.get(dataset)
    if manifest.holdout == "sealed" and args.tier == "full":
        if not args.prompt_digest or not args.policy_digest:
            raise ValueError("sealed full runs require --prompt-digest and --policy-digest")
    cache = registry.cache_path(dataset)
    if args.tier != "smoke":
        registry.verify(dataset)
    external = [str(args.external_runner.resolve())] if args.external_runner else None
    return AdapterRunRequest(
        dataset=dataset,
        tier=args.tier,
        seed=args.seed,
        supervisor_mode=args.supervisor_mode,
        prompt_digest=args.prompt_digest,
        policy_digest=args.policy_digest,
        environment_lock_digest=args.environment_lock_digest
        or _environment_lock_digest(manifest.native_environment),
        dataset_cache_path=str(cache) if cache.is_dir() else None,
        external_command=external,
    )


def _benchmark_command(args: argparse.Namespace) -> int:
    registry = _dataset_registry(args)
    names = [args.dataset] if args.benchmark_command == "run" else args.datasets
    all_results = []
    requests = []
    for name in names:
        request = _benchmark_request(args, name)
        adapter = registry.adapter(name)
        results = adapter.run(request)
        all_results.extend(results)
        requests.append(request.model_dump(mode="json"))
    report = separated_dataset_report(all_results)
    output_root = args.artifacts.resolve()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / f"dataset_benchmark_{timestamp}_{args.seed}_{uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=False)
    with (run_dir / "results.jsonl").open("w", encoding="utf-8") as handle:
        for result in all_results:
            payload = redact_value(result.model_dump(mode="json"))
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
    (run_dir / "summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (run_dir / "experiment_manifest.json").write_text(
        json.dumps(
            {
                "contract_version": "dataset-experiment-v1",
                "created_at": datetime.now(UTC).isoformat(),
                "requests": requests,
                "datasets": [registry.get(name).model_dump(mode="json") for name in names],
                "report_weighting": "separate_with_equal_dataset_macro",
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "run_dir": str(run_dir),
                "episodes": len(all_results),
                "summary": report,
            },
            indent=2,
        )
    )
    return 0


def _smoke(root: Path) -> int:
    artifacts = root / "artifacts"
    registry = default_registry(root, artifacts)
    runtime = TraceGuardRuntime(
        tools=registry,
        config=SafeguardConfig(
            defensive_prompt=True, deterministic_policy=True, llm_supervisor=True
        ),
        policy=DeterministicPolicy(load_default_policy()),
        supervisor=HeuristicSupervisor(),
    )
    call = ToolCall(
        task_id="smoke", step_id=0, tool_name="calculator", arguments={"expression": "12 * 7"}
    )
    result = ReActRunner(runtime, ScriptedAgent([call])).run("Calculate 12 times 7")
    print(
        json.dumps(
            {
                "stopped_reason": result.stopped_reason,
                "observations": [item.model_dump(mode="json") for item in result.observations],
            },
            indent=2,
        )
    )
    return 0


def _experiment(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    cases_path = args.cases.resolve() if args.cases else default_cases_path()
    ablations_path = args.ablations.resolve() if args.ablations else default_ablations_path()
    cases = load_cases(cases_path, split=args.split)
    ablations = load_ablations(ablations_path)
    if args.post_run:
        ablations = {
            name: config.model_copy(update={"post_run_reevaluation": True})
            for name, config in ablations.items()
        }
    ablation_filter = {args.ablation} if args.ablation else None
    case_filter = {args.case} if args.case else None
    artifacts_dir = (args.artifacts or (root / "artifacts")).resolve()
    results, report, run_dir = run_experiment(
        cases=cases,
        ablations=ablations,
        seed=args.seed,
        artifacts_dir=artifacts_dir,
        code_revision=args.code_revision,
        split=args.split,
        cases_path=cases_path,
        ablation_filter=ablation_filter,
        case_filter=case_filter,
        container_execution=args.container,
        sandbox_config_path=args.sandbox_config.resolve(),
        supervisor_provider=args.supervisor_provider,
        supervisor_model=args.supervisor_model,
        supervisor_url=args.supervisor_url,
        gemini_api_key=getattr(args, "gemini_api_key", None),
        gemini_base_url=getattr(args, "gemini_base_url", None),
        timeout=args.supervisor_timeout,
        supervisor_max_retries=args.supervisor_max_retries,
        supervisor_confidence_threshold=args.supervisor_confidence_threshold,
        supervisor_enable_rewrite=args.supervisor_enable_rewrite,
        agent_provider=args.agent_provider,
        agent_model=args.agent_model,
        agent_url=args.agent_url,
    )
    print(
        json.dumps(
            {
                "run_dir": str(run_dir),
                "n_results": len(results),
                "episode_metrics": report.episode,
                "by_threat_model": report.by_threat_model,
            },
            indent=2,
        )
    )
    return 0


def _smoke_matrix(root: Path, artifacts: Path | None, seed: int) -> int:
    cases = load_cases(default_cases_path(), split="all")
    selected = []
    for threat_model in sorted({case.threat_model for case in cases}, key=lambda item: item.value):
        selected.extend([case for case in cases if case.threat_model is threat_model][:5])
    results, report, run_dir = run_experiment(
        cases=selected,
        ablations=load_ablations(default_ablations_path()),
        seed=seed,
        artifacts_dir=(artifacts or (root / "artifacts")).resolve(),
        split="all",
        cases_path=default_cases_path(),
    )
    print(
        json.dumps(
            {
                "run_dir": str(run_dir),
                "n_results": len(results),
                "episode_metrics": report.episode,
            },
            indent=2,
        )
    )
    return 0


def _demo(args: argparse.Namespace) -> int:
    """Run a concise, camera-friendly comparison and save the full traces."""

    root = args.root.resolve()
    all_cases = load_cases(default_cases_path(), split="all")
    cases_by_id = {case.case_id: case for case in all_cases}
    selected_cases = [
        cases_by_id["benign_math_dev"],
        cases_by_id["indirect_document_instruction"],
    ]
    all_ablations = load_ablations(default_ablations_path())
    selected_ablations = {
        "A0_no_safeguards": all_ablations["A0"],
        "A7_full_hybrid": all_ablations["A7"],
    }
    results, _, run_dir = run_experiment(
        cases=selected_cases,
        ablations=selected_ablations,
        seed=args.seed,
        artifacts_dir=(args.artifacts or (root / "artifacts")).resolve(),
        split="all",
        cases_path=default_cases_path(),
        agent_provider="scripted",
        supervisor_provider="heuristic",
    )

    print("TRACEGUARD LIVE DEMO")
    print("====================")
    for result in results:
        print(f"\n[{result.ablation}] {result.case_id}")
        print(f"  threat model : {result.threat_model.value}")
        for trace in result.traces:
            proposed = trace["proposed_call"]
            decisions = [output["decision"] for output in trace.get("safeguard_outputs", [])] or [
                "NONE"
            ]
            print(
                f"  step {trace['step_id']}       : propose "
                f"{proposed['tool_name']}({json.dumps(proposed['arguments'], sort_keys=True)})"
            )
            print(f"                 supervisor={'+'.join(decisions)}")
            print(f"                 outcome={trace['episode_outcome']}")
        print(
            "  checks       : "
            f"utility={'PASS' if result.utility_passed else 'FAIL'}, "
            f"security={'PASS' if result.security_passed else 'FAIL'}"
        )

    baseline_attack = next(
        result
        for result in results
        if result.ablation == "A0_no_safeguards"
        and result.case_id == "indirect_document_instruction"
    )
    hybrid_attack = next(
        result
        for result in results
        if result.ablation == "A7_full_hybrid" and result.case_id == "indirect_document_instruction"
    )
    print("\nRESULT")
    print("------")
    print(
        "  Baseline indirect injection : "
        f"{'PREVENTED' if baseline_attack.security_passed else 'SUCCEEDED'}"
    )
    print(
        "  Hybrid indirect injection   : "
        f"{'PREVENTED' if hybrid_attack.security_passed else 'SUCCEEDED'}"
    )
    print(f"  Full sanitized traces        : {run_dir}")

    if getattr(args, "ollama", False):
        model = (
            getattr(args, "ollama_model", None)
            or os.getenv("TRACEGUARD_OLLAMA_MODEL")
            or "qwen3:4b"
        )
        ollama_url = getattr(args, "ollama_url", "http://127.0.0.1:11434")
        live_results, _, live_run_dir = run_experiment(
            cases=[cases_by_id["benign_math_dev"]],
            ablations={"A7_ollama_live": all_ablations["A7"]},
            seed=args.seed,
            artifacts_dir=(args.artifacts or (root / "artifacts")).resolve(),
            split="dev",
            cases_path=default_cases_path(),
            agent_provider="ollama",
            agent_model=model,
            agent_url=ollama_url,
            supervisor_provider="ollama",
            supervisor_model=model,
            supervisor_url=ollama_url,
        )
        live = live_results[0]
        print("\nOLLAMA LIVE CHECK")
        print("-----------------")
        print(f"  model        : {model}")
        print(f"  url          : {ollama_url}")
        print(f"  utility      : {'PASS' if live.utility_passed else 'FAIL'}")
        print(f"  security     : {'PASS' if live.security_passed else 'FAIL'}")
        print(f"  trace output : {live_run_dir}")
        if not (live.utility_passed and live.security_passed):
            return 1

    if not args.gemini:
        print("\nGemini live call skipped (add --gemini after configuring GEMINI_API_KEY).")
        return 0
    if not os.getenv("GEMINI_API_KEY"):
        print("\nGemini live call requested, but GEMINI_API_KEY is not set.", file=sys.stderr)
        return 2

    model = args.gemini_model or os.getenv("TRACEGUARD_GEMINI_MODEL") or "gemini-3.5-flash"
    live_results, _, live_run_dir = run_experiment(
        cases=[cases_by_id["benign_math_dev"]],
        ablations={"A7_gemini_live": all_ablations["A7"]},
        seed=args.seed,
        artifacts_dir=(args.artifacts or (root / "artifacts")).resolve(),
        split="dev",
        cases_path=default_cases_path(),
        agent_provider="gemini",
        agent_model=model,
        supervisor_provider="gemini",
        supervisor_model=model,
        gemini_api_key=os.getenv("GEMINI_API_KEY"),
        gemini_base_url=getattr(args, "gemini_base_url", None),
    )
    live = live_results[0]
    print("\nGEMINI LIVE CHECK")
    print("-----------------")
    print(f"  model        : {model}")
    base_url = getattr(args, "gemini_base_url", None) or os.getenv("GEMINI_BASE_URL") or "default"
    print(f"  base url     : {base_url}")
    print(f"  utility      : {'PASS' if live.utility_passed else 'FAIL'}")
    print(f"  security     : {'PASS' if live.security_passed else 'FAIL'}")
    print(f"  trace output : {live_run_dir}")
    return 0 if live.utility_passed and live.security_passed else 1


def _agentdojo_info(_: argparse.Namespace) -> int:
    selection = load_selection()
    payload: dict[str, object] = {"selection": selection}
    try:
        payload["installed"] = verify_agentdojo_installation()
        payload["validated_selection"] = validate_selection()
    except RuntimeError as exc:
        payload["installed"] = None
        payload["install_error"] = str(exc)
        print(json.dumps(payload, indent=2))
        return 1
    print(json.dumps(payload, indent=2))
    return 0


def _analyze(args: argparse.Namespace) -> int:
    results, report = regenerate_analysis_from_traces(args.run_dir.resolve())
    print(
        json.dumps(
            {
                "run_dir": str(args.run_dir.resolve()),
                "n_results": len(results),
                "episode_metrics": report.episode,
            },
            indent=2,
        )
    )
    return 0


def _sandbox_check(args: argparse.Namespace) -> int:
    runner = ContainerRunner(
        args.config.resolve(),
        workspace_root=args.root.resolve(),
        artifact_root=args.artifacts.resolve(),
    )
    try:
        architecture = runner.check_environment()
    except SandboxUnavailable as exc:
        print(json.dumps({"ready": False, "error": str(exc)}, indent=2))
        return 1
    print(
        json.dumps(
            {
                "ready": True,
                "architecture": architecture,
                "image": runner.image,
                "config_version": runner.config.version,
                "enabled_profiles": sorted(
                    name for name, profile in runner.config.profiles.items() if profile.enabled
                ),
            },
            indent=2,
        )
    )
    return 0


def _sandbox_benchmark(args: argparse.Namespace) -> int:
    config_path = args.config.resolve()
    runner = ContainerRunner(
        config_path,
        workspace_root=args.root.resolve(),
        artifact_root=args.artifacts.resolve(),
    )
    architecture = runner.check_environment()
    implementation_hasher = hashlib.sha256()
    for relative in (
        "src/traceguard/cli.py",
        "src/traceguard/runtime.py",
        "src/traceguard/sandbox/config.py",
        "src/traceguard/sandbox/runner.py",
        "src/traceguard/types.py",
    ):
        path = args.root.resolve() / relative
        implementation_hasher.update(relative.encode())
        implementation_hasher.update(path.read_bytes())
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=args.root.resolve(),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    durations: list[float] = []
    peak_memory: list[int] = []
    disk_usage: list[int] = []
    workload_ms = 1500
    for index in range(args.runs):
        call = ToolCall(
            task_id="sandbox-benchmark",
            step_id=index,
            tool_name="restricted_command",
            arguments={
                "command": [
                    "python3",
                    "-c",
                    "import time; print('traceguard-canary', flush=True); time.sleep(1.5)",
                ]
            },
        )
        evidence = runner.execute(
            ExecutionPlan(
                effective_call=call,
                target=ExecutionTarget.CONTAINER,
                sandbox_profile="isolated_compute",
                validated=True,
                validation_reason="fixed sandbox benchmark canary",
            )
        )
        if evidence.exit_code != 0 or evidence.stdout.strip() != "traceguard-canary":
            raise SandboxUnavailable("sandbox benchmark canary failed")
        durations.append(max(0.0, evidence.duration_ms - workload_ms))
        if evidence.peak_memory_bytes is not None:
            peak_memory.append(evidence.peak_memory_bytes)
        if evidence.disk_usage_bytes is not None:
            disk_usage.append(evidence.disk_usage_bytes)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "code_revision": revision.stdout.strip() if revision.returncode == 0 else "unknown",
        "implementation_sha256": implementation_hasher.hexdigest(),
        "config_version": runner.config.version,
        "config_path": str(config_path),
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "image": runner.image,
        "architecture": architecture,
        "host_platform": platform.platform(),
        "runs": args.runs,
        "fixed_workload_ms": workload_ms,
        "cold_start_ms": durations[0],
        "warm_mean_ms": statistics.fmean(durations[1:]) if len(durations) > 1 else None,
        "durations_ms": durations,
        "cleanup_successes": args.runs,
        "peak_memory_bytes": max(peak_memory) if peak_memory else None,
        "max_writable_layer_bytes": max(disk_usage) if disk_usage else None,
    }
    output = args.artifacts.resolve() / "sandbox_benchmark.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({**payload, "output": str(output)}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="traceguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dataset = subparsers.add_parser("dataset", help="manage pinned benchmark datasets")
    dataset.add_argument(
        "--cache-root",
        type=Path,
        default=Path(".cache/traceguard-datasets"),
    )
    dataset_commands = dataset.add_subparsers(dest="dataset_command", required=True)
    dataset_commands.add_parser("list", help="list dataset manifests")
    dataset_fetch = dataset_commands.add_parser("fetch", help="fetch a pinned upstream checkout")
    dataset_fetch.add_argument("name")
    dataset_verify = dataset_commands.add_parser("verify", help="verify fixture and checkout")
    dataset_verify.add_argument("name")
    dataset_verify.add_argument("--fixture-only", action="store_true")

    benchmark = subparsers.add_parser(
        "benchmark",
        help="run normalized external benchmark adapters",
    )
    benchmark_commands = benchmark.add_subparsers(dest="benchmark_command", required=True)
    benchmark_run = benchmark_commands.add_parser("run", help="run one dataset")
    benchmark_run.add_argument("--dataset", required=True)
    benchmark_matrix = benchmark_commands.add_parser("matrix", help="run datasets separately")
    benchmark_matrix.add_argument("--datasets", nargs="+", required=True)
    for benchmark_parser in (benchmark_run, benchmark_matrix):
        benchmark_parser.add_argument(
            "--cache-root",
            type=Path,
            default=Path(".cache/traceguard-datasets"),
        )
        benchmark_parser.add_argument("--artifacts", type=Path, default=Path("artifacts"))
        benchmark_parser.add_argument(
            "--tier",
            choices=["smoke", "standard", "full"],
            default="smoke",
        )
        benchmark_parser.add_argument("--seed", type=int, default=0)
        benchmark_parser.add_argument(
            "--supervisor-mode",
            choices=["none", "deterministic"],
            default="deterministic",
        )
        benchmark_parser.add_argument("--prompt-digest")
        benchmark_parser.add_argument("--policy-digest")
        benchmark_parser.add_argument("--environment-lock-digest")
        benchmark_parser.add_argument("--external-runner", type=Path)

    smoke = subparsers.add_parser("smoke", help="run an offline supervised episode")
    smoke.add_argument("--root", type=Path, default=Path.cwd())

    smoke_matrix = subparsers.add_parser(
        "smoke-matrix",
        help="run five cases per threat model across all eight ablations",
    )
    smoke_matrix.add_argument("--root", type=Path, default=Path.cwd())
    smoke_matrix.add_argument("--artifacts", type=Path, default=None)
    smoke_matrix.add_argument("--seed", type=int, default=0)

    demo = subparsers.add_parser(
        "demo",
        help="run a concise benign/baseline/hybrid comparison for the submission video",
    )
    demo.add_argument("--root", type=Path, default=Path.cwd())
    demo.add_argument("--artifacts", type=Path, default=None)
    demo.add_argument("--seed", type=int, default=0)
    demo.add_argument(
        "--gemini",
        action="store_true",
        help="also run one live Gemini agent and supervisor episode",
    )
    demo.add_argument("--gemini-model", default=None)
    demo.add_argument("--gemini-base-url", default=None)
    demo.add_argument(
        "--ollama",
        action="store_true",
        help="also run one live Ollama/Qwen agent and supervisor episode",
    )
    demo.add_argument("--ollama-model", default=None)
    demo.add_argument("--ollama-url", default="http://127.0.0.1:11434")

    experiment = subparsers.add_parser(
        "experiment",
        help="run one case, one ablation, or the full safeguard matrix",
    )
    experiment.add_argument("--root", type=Path, default=Path.cwd())
    experiment.add_argument("--cases", type=Path, default=None)
    experiment.add_argument("--ablations", type=Path, default=None)
    experiment.add_argument("--artifacts", type=Path, default=None)
    experiment.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    experiment.add_argument("--ablation", type=str, default=None, help="e.g. A2")
    experiment.add_argument("--case", type=str, default=None, help="single case_id")
    experiment.add_argument("--seed", type=int, default=0)
    experiment.add_argument("--code-revision", type=str, default=None)
    experiment.add_argument(
        "--agent-provider",
        choices=["scripted", "ollama", "gemini"],
        default="ollama",
    )
    experiment.add_argument("--agent-model", default=None)
    experiment.add_argument("--agent-url", default=None)
    experiment.add_argument(
        "--supervisor-provider",
        choices=["ollama", "gemini", "heuristic"],
        default="ollama",
    )
    experiment.add_argument("--supervisor-model", default=None)
    experiment.add_argument("--supervisor-url", default=None)
    experiment.add_argument("--gemini-api-key", default=None)
    experiment.add_argument("--gemini-base-url", default=None)
    experiment.add_argument("--supervisor-timeout", type=float, default=60.0)
    experiment.add_argument("--supervisor-max-retries", type=int, default=2)
    experiment.add_argument("--supervisor-confidence-threshold", type=float, default=0.55)
    experiment.add_argument("--supervisor-enable-rewrite", action="store_true")
    experiment.add_argument(
        "--container",
        action="store_true",
        help="execute approved container routes instead of failing closed",
    )
    experiment.add_argument(
        "--sandbox-config",
        type=Path,
        default=default_sandbox_configuration_path(),
    )
    experiment.add_argument(
        "--post-run",
        action="store_true",
        help="enable exploratory supervisor reevaluation of container evidence",
    )

    analyze = subparsers.add_parser(
        "analyze",
        help="regenerate summary.json and summary.csv from sanitized traces",
    )
    analyze.add_argument("--run-dir", type=Path, required=True)

    subparsers.add_parser(
        "agentdojo-info",
        help="show pinned AgentDojo selection and installation status",
    )

    sandbox_check = subparsers.add_parser(
        "sandbox-check",
        help="verify Docker, architecture, image digest, and trusted profiles",
    )
    sandbox_check.add_argument("--root", type=Path, default=Path.cwd())
    sandbox_check.add_argument(
        "--config",
        type=Path,
        default=default_sandbox_configuration_path(),
    )
    sandbox_check.add_argument(
        "--artifacts",
        type=Path,
        default=Path.cwd() / "artifacts",
    )

    sandbox_benchmark = subparsers.add_parser(
        "sandbox-benchmark",
        help="measure cold/warm containment latency and cleanup reliability",
    )
    sandbox_benchmark.add_argument("--root", type=Path, default=Path.cwd())
    sandbox_benchmark.add_argument(
        "--config",
        type=Path,
        default=default_sandbox_configuration_path(),
    )
    sandbox_benchmark.add_argument(
        "--artifacts",
        type=Path,
        default=Path.cwd() / "artifacts",
    )
    sandbox_benchmark.add_argument("--runs", type=int, choices=range(1, 101), default=5)

    subparsers.add_parser(
        "ablation",
        help="run a four-mode custom or AgentDojo ablation",
    )
    subparsers.add_parser(
        "conclusion-ablation",
        help="run the conclusion-focused AgentDojo ablation matrix",
    )

    command_argv = sys.argv[1:] if argv is None else argv
    if command_argv[:1] == ["ablation"]:
        from traceguard.run_ablation import main as ablation_main

        return ablation_main(command_argv[1:])
    if command_argv[:1] == ["conclusion-ablation"]:
        from traceguard.conclusion_ablation import main as conclusion_main

        return conclusion_main(command_argv[1:])

    args = parser.parse_args(command_argv)
    if args.command == "dataset":
        return _dataset_command(args)
    if args.command == "benchmark":
        try:
            return _benchmark_command(args)
        except (KeyError, RuntimeError, ValueError) as exc:
            print(json.dumps({"completed": False, "error": str(exc)}, indent=2))
            return 1
    if args.command == "smoke":
        return _smoke(args.root.resolve())
    if args.command == "smoke-matrix":
        return _smoke_matrix(args.root.resolve(), args.artifacts, args.seed)
    if args.command == "demo":
        return _demo(args)
    if args.command == "experiment":
        return _experiment(args)
    if args.command == "agentdojo-info":
        return _agentdojo_info(args)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "sandbox-check":
        return _sandbox_check(args)
    if args.command == "sandbox-benchmark":
        try:
            return _sandbox_benchmark(args)
        except SandboxUnavailable as exc:
            print(json.dumps({"completed": False, "error": str(exc)}, indent=2))
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
