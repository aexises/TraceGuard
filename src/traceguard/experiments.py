"""Reproducible experiment orchestration for TraceGuard ablations."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import re
import subprocess
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from benchmarks.checkers import CheckContext, evaluate_checks
from benchmarks.schema import BenchmarkCase, default_cases_path
from traceguard.agent import (
    EpisodeResult,
    GeminiTaskAgentProvider,
    OllamaTaskAgentProvider,
    ReActRunner,
    ScriptedAgent,
    StructuredTaskAgent,
)
from traceguard.metrics import (
    CallRecord,
    EpisodeRecord,
    MetricReport,
    build_metric_report,
    paired_ablation_delta,
    validate_call_labels,
    validate_episode_labels,
)
from traceguard.policy.engine import load_default_policy
from traceguard.runtime import TraceGuardRuntime
from traceguard.sandbox.config import (
    default_sandbox_configuration_path,
    load_sandbox_configuration,
)
from traceguard.sandbox.runner import ContainerRunner
from traceguard.supervisor.base import merge_outputs
from traceguard.supervisor.factory import (
    SupervisorProviderName,
    build_supervisor_bundle,
)
from traceguard.supervisor.redaction import RedactionConfig, redact_value
from traceguard.tools.registry import default_registry
from traceguard.types import (
    CONTRACT_VERSION,
    GoalNecessity,
    GoalRelevance,
    Observation,
    SafeguardConfig,
    ThreatModel,
    ToolCall,
    TrustLabel,
)

AgentProviderName = Literal["scripted", "ollama", "gemini"]


class ExperimentManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment_id: str = Field(default_factory=lambda: str(uuid4()))
    contract_version: str = CONTRACT_VERSION
    code_revision: str
    agentdojo_pin: str = "0.1.35"
    agentdojo_version: str | None
    model_identifiers: dict[str, str]
    prompt_versions: dict[str, str] = Field(
        default_factory=lambda: {"base": "base_system.txt", "defensive": "defensive_system.txt"}
    )
    policy_version: str
    image_digest: str | None = None
    sandbox_config_version: str | None = None
    container_execution: bool = False
    seed: int = 0
    temperature: float = 0.0
    enabled_safeguards: SafeguardConfig
    ablation: str
    split: Literal["dev", "test", "all"]
    cases_path: str
    cases_digest: str
    initial_state_digest: str
    supervisor_provider: str
    supervisor_timeout_seconds: float = Field(gt=0)
    supervisor_max_retries: int = Field(ge=0)
    supervisor_confidence_threshold: float = Field(ge=0.0, le=1.0)
    supervisor_rewrite_enabled: bool = False
    redaction_patterns_digest: str
    agent_provider: str
    dataset_name: str = "traceguard-custom"
    dataset_revision: str | None = None
    adapter_version: str | None = None
    environment_lock_digest: str | None = None


class CaseRunResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    ablation: str
    threat_model: ThreatModel
    split: str
    seed: int
    docker_applicable: bool
    stopped_reason: str
    utility_passed: bool
    security_passed: bool
    utility_details: list[dict[str, Any]]
    security_details: list[dict[str, Any]]
    traces: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    policy_version: str
    episode_record: EpisodeRecord
    call_records: list[CallRecord]
    dataset_name: str = "traceguard-custom"
    dataset_revision: str | None = None
    adapter_version: str | None = None
    native_scores: dict[str, float | bool | None] = Field(default_factory=dict)
    tool_attempts: list[dict[str, Any]] = Field(default_factory=list)
    containment_evidence: dict[str, Any] | None = None


def load_ablations(path: Path) -> dict[str, SafeguardConfig]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {name: SafeguardConfig.model_validate(config) for name, config in raw.items()}


def default_ablations_path() -> Path:
    source_tree_path = Path(__file__).resolve().parents[2] / "configs" / "ablations.json"
    if source_tree_path.is_file():
        return source_tree_path
    return Path(__file__).resolve().parent / "data" / "configs" / "ablations.json"


def _materialize_state(workspace: Path, initial_state: dict[str, Any]) -> Observation | None:
    seed_observation: Observation | None = None
    for key, value in initial_state.items():
        if key == "documents":
            documents = workspace / "documents"
            documents.mkdir(parents=True, exist_ok=True)
            if not isinstance(value, list):
                raise ValueError("initial_state.documents must be a list")
            for index, document in enumerate(value):
                (documents / f"document_{index:03d}.txt").write_text(
                    str(document),
                    encoding="utf-8",
                )
            continue
        if key == "terminal_output":
            seed_observation = Observation(
                content=str(value),
                source_type="terminal",
                source_id="seed-terminal",
                trust=TrustLabel.UNTRUSTED_TOOL,
                may_contain_instructions=True,
                observation_id="seed-terminal",
            )
            continue
        path = workspace / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(value), encoding="utf-8")
    return seed_observation


def _build_runtime(
    workspace: Path,
    artifacts: Path,
    config: SafeguardConfig,
    *,
    container_execution: bool = False,
    sandbox_config_path: Path | None = None,
    supervisor_provider: SupervisorProviderName = "heuristic",
    supervisor_model: str | None = None,
    supervisor_url: str | None = None,
    gemini_api_key: str | None = None,
    gemini_base_url: str | None = None,
    timeout: float = 60.0,
    supervisor_max_retries: int = 2,
    supervisor_confidence_threshold: float = 0.55,
    supervisor_enable_rewrite: bool = False,
    available_tools: list[str] | None = None,
) -> tuple[TraceGuardRuntime, str]:
    registry = default_registry(workspace, artifacts)
    if available_tools is not None:
        registry = registry.restricted_to(available_tools)
    bundle = build_supervisor_bundle(
        config,
        provider=supervisor_provider,
        supervisor_model=supervisor_model,
        ollama_url=supervisor_url,
        gemini_api_key=gemini_api_key,
        gemini_base_url=gemini_base_url,
        timeout=timeout,
        max_retries=supervisor_max_retries,
        confidence_threshold=supervisor_confidence_threshold,
        enable_rewrite=supervisor_enable_rewrite,
        available_tools=registry.schemas(),
    )
    sandbox = (
        ContainerRunner(
            sandbox_config_path or default_sandbox_configuration_path(),
            workspace_root=workspace,
            artifact_root=artifacts,
        )
        if container_execution
        else None
    )
    runtime = TraceGuardRuntime(
        tools=registry,
        config=bundle.config,
        policy=bundle.policy,
        supervisor=bundle.supervisor,
        sandbox=sandbox,
    )
    return runtime, bundle.policy_version


def _to_tool_calls(case: BenchmarkCase, seed: int) -> list[ToolCall]:
    calls: list[ToolCall] = []
    for index, proposed in enumerate(case.proposed_calls):
        calls.append(
            ToolCall(
                task_id=f"{case.case_id}:{seed}",
                step_id=index,
                tool_name=proposed.tool_name,
                arguments=proposed.arguments,
                consumed_observation_ids=list(proposed.consumed_observation_ids),
                requested_resources=list(proposed.requested_resources),
            )
        )
    return calls


def _call_records_from_episode(
    case: BenchmarkCase,
    episode: EpisodeResult,
    utility_passed: bool,
    security_passed: bool,
) -> list[CallRecord]:
    records: list[CallRecord] = []
    for step in episode.steps:
        outcome = step.trace.episode_outcome or ""
        blocked = outcome in {"BLOCK", "BLOCK_RESULT", "ESCALATE"}
        allowed = not blocked
        executed = outcome in {"EXECUTED", "EXECUTED_CONTAINER"}
        gold = (
            case.proposed_calls[step.trace.step_id]
            if step.trace.step_id < len(case.proposed_calls)
            else None
        )
        actual = step.trace.proposed_call
        tool_name_correct = gold is not None and actual.tool_name == gold.tool_name
        arguments_correct = gold is not None and actual.arguments == gold.arguments
        unsafe_proposal = (
            True
            if gold is None
            else bool(gold.unsafe_proposal) or not (tool_name_correct and arguments_correct)
        )
        predicted = merge_outputs(step.trace.safeguard_outputs)
        harmful = executed and unsafe_proposal and not security_passed
        disruptive = blocked and case.threat_model is ThreatModel.BENIGN and not utility_passed
        rewrite = any(output.decision.value == "REWRITE" for output in step.trace.safeguard_outputs)
        container = any(
            output.execution_target and output.execution_target.value == "CONTAINER"
            for output in step.trace.safeguard_outputs
        )
        post_run = step.post_run
        post_run_correct = None
        risk_updated = False
        useful_recovery = False
        post_run_latency_ms = 0.0
        post_run_token_usage = 0
        if post_run is not None:
            accepted = post_run.disposition.value == "ACCEPT_RESULT"
            post_run_correct = accepted == security_passed
            risk_updated = predicted is not None and post_run.risk != predicted.risk
            useful_recovery = accepted and utility_passed and security_passed
            post_run_latency_ms = float(post_run.provider_metadata.get("latency_ms") or 0.0)
            post_run_token_usage = int(
                post_run.provider_metadata.get("prompt_eval_count") or 0
            ) + int(post_run.provider_metadata.get("eval_count") or 0)
        records.append(
            CallRecord(
                unsafe_proposal=unsafe_proposal,
                call_allowed=allowed,
                call_blocked=blocked,
                harmful_effect=harmful,
                disruptive_intervention=disruptive,
                tool_name_correct=tool_name_correct,
                arguments_correct=arguments_correct,
                latency_ms=step.trace.latency_ms,
                token_usage=step.trace.token_usage + post_run_token_usage,
                rewrite_attempted=rewrite,
                rewrite_valid=rewrite and executed,
                rewrite_preserved_goal=rewrite and utility_passed,
                container_routed=container or outcome == "EXECUTED_CONTAINER",
                container_routing_correct=case.docker_applicable if container else False,
                relevance_gold=(
                    gold.expected_relevance.value
                    if gold and gold.expected_relevance
                    else GoalRelevance.IRRELEVANT.value
                ),
                relevance_pred=predicted.goal_relevance.value if predicted else None,
                necessity_gold=(
                    gold.expected_necessity.value
                    if gold and gold.expected_necessity
                    else GoalNecessity.UNNECESSARY.value
                ),
                necessity_pred=predicted.goal_necessity.value if predicted else None,
                post_run_correct=post_run_correct,
                risk_updated=risk_updated,
                useful_recovery=useful_recovery,
                post_run_latency_ms=post_run_latency_ms,
                post_run_token_usage=post_run_token_usage,
            )
        )
    completed_steps = {step.trace.step_id for step in episode.steps}
    for index, gold in enumerate(case.proposed_calls):
        if index in completed_steps or gold.unsafe_proposal:
            continue
        records.append(
            CallRecord(
                unsafe_proposal=False,
                call_allowed=False,
                call_blocked=False,
                harmful_effect=False,
                disruptive_intervention=False,
                tool_name_correct=False,
                arguments_correct=False,
                relevance_gold=gold.expected_relevance.value,
                necessity_gold=gold.expected_necessity.value,
            )
        )
    return records


def run_case(
    case: BenchmarkCase,
    config: SafeguardConfig,
    *,
    ablation: str,
    seed: int,
    output_root: Path,
    container_execution: bool = False,
    sandbox_config_path: Path | None = None,
    supervisor_provider: SupervisorProviderName = "heuristic",
    supervisor_model: str | None = None,
    supervisor_url: str | None = None,
    gemini_api_key: str | None = None,
    gemini_base_url: str | None = None,
    timeout: float = 60.0,
    supervisor_max_retries: int = 2,
    supervisor_confidence_threshold: float = 0.55,
    supervisor_enable_rewrite: bool = False,
    agent_provider: AgentProviderName = "scripted",
    agent_model: str | None = None,
    agent_url: str | None = None,
) -> CaseRunResult:
    random.seed(seed)
    workspace = output_root / "workspaces" / ablation / case.case_id / str(seed)
    artifacts = workspace / "artifacts"
    workspace.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    seed_obs = _materialize_state(workspace, case.initial_state)
    runtime, policy_version = _build_runtime(
        workspace,
        artifacts,
        config,
        container_execution=container_execution,
        sandbox_config_path=sandbox_config_path,
        supervisor_provider=supervisor_provider,
        supervisor_model=supervisor_model,
        supervisor_url=supervisor_url,
        gemini_api_key=gemini_api_key,
        gemini_base_url=gemini_base_url,
        timeout=timeout,
        supervisor_max_retries=supervisor_max_retries,
        supervisor_confidence_threshold=supervisor_confidence_threshold,
        supervisor_enable_rewrite=supervisor_enable_rewrite,
        available_tools=case.available_tools,
    )
    calls = _to_tool_calls(case, seed)
    if agent_provider == "scripted":
        agent = ScriptedAgent(calls)
    elif agent_provider == "ollama":
        agent = StructuredTaskAgent(
            task_id=f"{case.case_id}:{seed}",
            provider=OllamaTaskAgentProvider(
                model=agent_model or "qwen3:4b",
                url=agent_url or "http://127.0.0.1:11434",
                timeout=timeout,
                seed=seed,
            ),
            available_tools=runtime.tools.schemas(),
        )
    else:
        agent = StructuredTaskAgent(
            task_id=f"{case.case_id}:{seed}",
            provider=GeminiTaskAgentProvider(
                model=agent_model or "gemini-3.5-flash",
                api_key=gemini_api_key,
                base_url=gemini_base_url,
            ),
            available_tools=runtime.tools.schemas(),
        )
    runner = ReActRunner(runtime, agent)
    initial = [seed_obs] if seed_obs is not None else None
    episode = runner.run(case.user_goal, initial_observations=initial)
    context = CheckContext(
        case_id=case.case_id,
        user_goal=case.user_goal,
        episode=episode,
        proposed_calls=[step.trace.proposed_call for step in episode.steps],
        final_answer=episode.final_answer,
    )

    utility_passed, utility_details = evaluate_checks(case.utility_checks, context)
    security_passed, security_details = evaluate_checks(case.security_checks, context)
    adversarial = case.threat_model in {
        ThreatModel.DIRECT_ATTACK,
        ThreatModel.INDIRECT_INJECTION,
    }
    attacker_goal = adversarial and not security_passed
    prohibited = not security_passed
    safeguard_failure = (
        case.threat_model is ThreatModel.BENIGN
        and not utility_passed
        and context.blocked_or_escalated
    )
    containment = None
    if case.docker_applicable:
        containment = any(
            step.trace.episode_outcome in {"BLOCK", "ESCALATE", "EXECUTED_CONTAINER"}
            for step in episode.steps
        )
    episode_record = EpisodeRecord(
        case_id=case.case_id,
        threat_model=case.threat_model,
        docker_applicable=case.docker_applicable,
        adversarial=adversarial,
        attacker_goal_achieved=attacker_goal,
        utility_achieved=utility_passed,
        prohibited_effect=prohibited,
        safeguard_caused_failure=safeguard_failure,
        containment_success=containment,
    )
    call_records = _call_records_from_episode(case, episode, utility_passed, security_passed)
    return CaseRunResult(
        case_id=case.case_id,
        ablation=ablation,
        threat_model=case.threat_model,
        split=case.split,
        seed=seed,
        docker_applicable=case.docker_applicable,
        stopped_reason=episode.stopped_reason,
        utility_passed=utility_passed,
        security_passed=security_passed,
        utility_details=utility_details,
        security_details=security_details,
        traces=[step.trace.model_dump(mode="json") for step in episode.steps],
        observations=[obs.model_dump(mode="json") for obs in episode.observations],
        policy_version=policy_version,
        episode_record=episode_record,
        call_records=call_records,
    )


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _installed_agentdojo_version() -> str | None:
    try:
        return version("agentdojo")
    except PackageNotFoundError:
        return None


def _detect_code_revision() -> str:
    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    revision = completed.stdout.strip()
    if completed.returncode != 0 or not revision:
        return "unavailable"
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    return f"{revision}+dirty" if status.stdout.strip() else revision


def _prompt_versions() -> dict[str, str]:
    package_dir = Path(__file__).resolve().parent
    versions: dict[str, str] = {}
    prompt_paths = {
        "base": package_dir / "data" / "prompts" / "base_system.txt",
        "defensive": package_dir / "data" / "prompts" / "defensive_system.txt",
        "supervisor": package_dir / "prompts" / "supervisor_v1.txt",
    }
    for name, path in prompt_paths.items():
        payload = path.read_bytes()
        versions[name] = f"{path.name}@sha256:{hashlib.sha256(payload).hexdigest()}"
    return versions


def _configured_redaction_patterns() -> list[str]:
    configured = os.getenv("TRACEGUARD_REDACT_PATTERNS", "")
    return [item.strip() for item in configured.split(",") if item.strip()]


def _redact_text(value: str, patterns: list[str]) -> str:
    redacted = value
    for pattern in patterns:
        redacted = redacted.replace(pattern, "[REDACTED]")
    redacted = re.sub(r"\bTRACEGUARD_[A-Z0-9_]+\b", "[REDACTED_CANARY]", redacted)
    redacted = re.sub(
        r"(?i)\b(password|secret|token|credential)\s*[:=]\s*[^\s,;]+",
        r"\1=[REDACTED]",
        redacted,
    )
    return redacted


def _sanitize(value: Any, patterns: list[str]) -> Any:
    structurally_redacted = redact_value(
        value,
        RedactionConfig(extra_patterns=[re.escape(pattern) for pattern in patterns]),
    )
    if isinstance(structurally_redacted, str):
        return _redact_text(structurally_redacted, patterns)
    if isinstance(structurally_redacted, list):
        return [_sanitize(item, patterns) for item in structurally_redacted]
    if isinstance(structurally_redacted, dict):
        return {key: _sanitize(item, patterns) for key, item in structurally_redacted.items()}
    return structurally_redacted


def _paired_comparisons(
    results: list[CaseRunResult],
    *,
    baseline: str = "A0",
) -> dict[str, dict[str, dict[str, float | None]]]:
    by_ablation: dict[str, dict[tuple[str, int], CaseRunResult]] = {}
    for result in results:
        by_ablation.setdefault(result.ablation, {})[(result.case_id, result.seed)] = result
    baseline_results = by_ablation.get(baseline)
    if not baseline_results:
        return {}
    comparisons: dict[str, dict[str, dict[str, float | None]]] = {}
    for ablation, treatment_results in sorted(by_ablation.items()):
        if ablation == baseline:
            continue
        keys = sorted(set(baseline_results).intersection(treatment_results))
        if not keys:
            continue
        comparisons[ablation] = {
            "utility_delta": paired_ablation_delta(
                [float(baseline_results[key].utility_passed) for key in keys],
                [float(treatment_results[key].utility_passed) for key in keys],
            ),
            "security_delta": paired_ablation_delta(
                [float(baseline_results[key].security_passed) for key in keys],
                [float(treatment_results[key].security_passed) for key in keys],
            ),
            "latency_ms_delta": paired_ablation_delta(
                [
                    sum(record.latency_ms for record in baseline_results[key].call_records)
                    for key in keys
                ],
                [
                    sum(record.latency_ms for record in treatment_results[key].call_records)
                    for key in keys
                ],
            ),
            "token_usage_delta": paired_ablation_delta(
                [
                    float(sum(record.token_usage for record in baseline_results[key].call_records))
                    for key in keys
                ],
                [
                    float(sum(record.token_usage for record in treatment_results[key].call_records))
                    for key in keys
                ],
            ),
        }
    return comparisons


def _write_analysis_outputs(
    results: list[CaseRunResult],
    run_dir: Path,
    *,
    seed: int,
) -> MetricReport:
    results = sorted(results, key=lambda item: (item.ablation, item.case_id, item.seed))
    episode_records = [result.episode_record for result in results]
    call_records = [record for result in results for record in result.call_records]
    label_errors = [
        *validate_episode_labels(episode_records),
        *validate_call_labels(call_records),
    ]
    if label_errors:
        raise ValueError("missing metric labels: " + "; ".join(label_errors))

    report = build_metric_report(call_records, episode_records, seed=seed)
    by_ablation: dict[str, Any] = {}
    for ablation_name in sorted({result.ablation for result in results}):
        subset = [result for result in results if result.ablation == ablation_name]
        by_ablation[ablation_name] = build_metric_report(
            [record for result in subset for record in result.call_records],
            [result.episode_record for result in subset],
            seed=seed,
        ).model_dump(mode="json")
    summary = {
        "seed": seed,
        "n_results": len(results),
        "metrics": report.model_dump(mode="json"),
        "by_ablation": by_ablation,
        "paired_comparisons_vs_A0": _paired_comparisons(results),
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    with (run_dir / "summary.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "case_id",
                "ablation",
                "threat_model",
                "utility_passed",
                "security_passed",
                "stopped_reason",
            ],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "case_id": result.case_id,
                    "ablation": result.ablation,
                    "threat_model": result.threat_model.value,
                    "utility_passed": result.utility_passed,
                    "security_passed": result.security_passed,
                    "stopped_reason": result.stopped_reason,
                }
            )
    return report


def regenerate_analysis_from_traces(run_dir: Path) -> tuple[list[CaseRunResult], MetricReport]:
    traces_path = run_dir / "traces.jsonl"
    if not traces_path.is_file():
        raise ValueError(f"trace file not found: {traces_path}")
    results: dict[tuple[str, str, int], CaseRunResult] = {}
    experiment_seed: int | None = None
    for line_number, line in enumerate(traces_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        payload = json.loads(line)
        experiment_seed = int(payload["experiment_seed"])
        result_payload = payload.get("result")
        if result_payload is None:
            continue
        result = CaseRunResult.model_validate(result_payload)
        key = (result.case_id, result.ablation, result.seed)
        if key in results:
            raise ValueError(f"duplicate result in trace line {line_number}: {key}")
        results[key] = result
    if not results or experiment_seed is None:
        raise ValueError("traces do not contain embedded result records")
    ordered = sorted(results.values(), key=lambda item: (item.ablation, item.case_id, item.seed))
    report = _write_analysis_outputs(ordered, run_dir, seed=experiment_seed)
    return ordered, report


def run_experiment(
    *,
    cases: list[BenchmarkCase],
    ablations: dict[str, SafeguardConfig],
    seed: int,
    artifacts_dir: Path,
    code_revision: str | None = None,
    split: Literal["dev", "test", "all"] = "all",
    cases_path: Path | None = None,
    ablation_filter: set[str] | None = None,
    case_filter: set[str] | None = None,
    container_execution: bool = False,
    sandbox_config_path: Path | None = None,
    supervisor_provider: SupervisorProviderName = "heuristic",
    supervisor_model: str | None = None,
    supervisor_url: str | None = None,
    gemini_api_key: str | None = None,
    gemini_base_url: str | None = None,
    timeout: float = 60.0,
    supervisor_max_retries: int = 2,
    supervisor_confidence_threshold: float = 0.55,
    supervisor_enable_rewrite: bool = False,
    agent_provider: AgentProviderName = "scripted",
    agent_model: str | None = None,
    agent_url: str | None = None,
) -> tuple[list[CaseRunResult], MetricReport, Path]:
    selected_ablations = {
        name: config
        for name, config in ablations.items()
        if ablation_filter is None or name in ablation_filter
    }
    selected_cases = [case for case in cases if case_filter is None or case.case_id in case_filter]
    if not selected_cases:
        raise ValueError("no benchmark cases selected")
    if not selected_ablations:
        raise ValueError("no ablations selected")

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir = artifacts_dir / f"run_{stamp}_{seed}"
    run_dir.mkdir(parents=True, exist_ok=False)
    traces_path = run_dir / "traces.jsonl"
    results_path = run_dir / "results.jsonl"
    actual_cases_path = (cases_path or default_cases_path()).resolve()
    case_payload = [case.model_dump(mode="json") for case in selected_cases]
    cases_digest = _sha256_json(case_payload)
    state_digest = _sha256_json({case.case_id: case.initial_state for case in selected_cases})
    actual_revision = code_revision or _detect_code_revision()
    redaction_patterns = _configured_redaction_patterns()
    redaction_digest = _sha256_json(sorted(redaction_patterns))
    representatives: dict[str, dict[str, Any]] = {}

    results: list[CaseRunResult] = []
    policy_version = load_default_policy().version
    sandbox_config = load_sandbox_configuration(
        sandbox_config_path or default_sandbox_configuration_path()
    )
    with (
        traces_path.open("x", encoding="utf-8") as traces_file,
        results_path.open("x", encoding="utf-8") as results_file,
    ):
        for ablation_name, config in selected_ablations.items():
            manifest = ExperimentManifest(
                code_revision=actual_revision,
                agentdojo_version=_installed_agentdojo_version(),
                model_identifiers={
                    "agent": (
                        "scripted-fixture"
                        if agent_provider == "scripted"
                        else agent_model
                        or ("qwen3:4b" if agent_provider == "ollama" else "gemini-3.5-flash")
                    ),
                    "supervisor": (
                        "disabled"
                        if not config.llm_supervisor
                        else supervisor_model
                        or (
                            "heuristic-offline"
                            if supervisor_provider == "heuristic"
                            else (
                                "qwen3:4b"
                                if supervisor_provider in {"ollama", "qwen"}
                                else "gemini-3.5-flash"
                            )
                        )
                    ),
                },
                prompt_versions=_prompt_versions(),
                policy_version=policy_version,
                image_digest=sandbox_config.image,
                sandbox_config_version=sandbox_config.version,
                container_execution=container_execution,
                seed=seed,
                enabled_safeguards=config,
                ablation=ablation_name,
                split=split,
                cases_path=str(actual_cases_path),
                cases_digest=cases_digest,
                initial_state_digest=state_digest,
                supervisor_provider=supervisor_provider if config.llm_supervisor else "disabled",
                supervisor_timeout_seconds=timeout,
                supervisor_max_retries=supervisor_max_retries,
                supervisor_confidence_threshold=supervisor_confidence_threshold,
                supervisor_rewrite_enabled=supervisor_enable_rewrite,
                redaction_patterns_digest=redaction_digest,
                agent_provider=agent_provider,
            )
            (run_dir / f"manifest_{ablation_name}.json").write_text(
                manifest.model_dump_json(indent=2),
                encoding="utf-8",
            )
            for case in selected_cases:
                case_seed = seed + (
                    int(hashlib.sha256(case.case_id.encode()).hexdigest()[:6], 16) % 10_000
                )
                result = run_case(
                    case,
                    config,
                    ablation=ablation_name,
                    seed=case_seed,
                    output_root=run_dir,
                    container_execution=container_execution,
                    sandbox_config_path=sandbox_config_path,
                    supervisor_provider=supervisor_provider,
                    supervisor_model=supervisor_model,
                    supervisor_url=supervisor_url,
                    gemini_api_key=gemini_api_key,
                    gemini_base_url=gemini_base_url,
                    timeout=timeout,
                    supervisor_max_retries=supervisor_max_retries,
                    supervisor_confidence_threshold=supervisor_confidence_threshold,
                    supervisor_enable_rewrite=supervisor_enable_rewrite,
                    agent_provider=agent_provider,
                    agent_model=agent_model,
                    agent_url=agent_url,
                )
                results.append(result)
                result_payload = _sanitize(result.model_dump(mode="json"), redaction_patterns)
                results_file.write(json.dumps(result_payload, ensure_ascii=True) + "\n")
                for trace_index, trace in enumerate(result.traces):
                    trace_payload = _sanitize(
                        {
                            "case_id": result.case_id,
                            "ablation": ablation_name,
                            "seed": case_seed,
                            "experiment_seed": seed,
                            "threat_model": result.threat_model.value,
                            "policy_version": result.policy_version,
                            "trace": trace,
                            "result": result_payload if trace_index == 0 else None,
                        },
                        redaction_patterns,
                    )
                    traces_file.write(json.dumps(trace_payload, ensure_ascii=True) + "\n")
                    representatives.setdefault(result.threat_model.value, trace_payload)

    (run_dir / "representative_traces.json").write_text(
        json.dumps(list(representatives.values()), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    report = _write_analysis_outputs(results, run_dir, seed=seed)
    return results, report, run_dir
