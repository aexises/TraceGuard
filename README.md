# TraceGuard

TraceGuard is a research runtime for evaluating system-prompt defenses, deterministic policy, and LLM supervision for tool-using agents. Docker is used only as a conditional containment mechanism for uncertain, medium-risk command calls.

The reproducible results narrative is in
[`docs/evaluation_report.md`](docs/evaluation_report.md), and the short walkthrough is
in [`docs/demo.md`](docs/demo.md). Supervisor precedence and label semantics are in
[`docs/contracts.md`](docs/contracts.md); confidence handling is documented in
[`docs/supervisor_calibration.md`](docs/supervisor_calibration.md). Dataset acquisition,
native environments, tool inventory, safety controls, and score interpretation are in
[`docs/external_benchmarks.md`](docs/external_benchmarks.md).

## Setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
ruff format --check .
```

Install `.[gemini]`, `.[agentdojo]`, or both for external evaluations. Gemini
credentials belong in `GEMINI_API_KEY`; set `GEMINI_BASE_URL` for OpenAI-compatible
gateways such as `https://open.blackroute.space/v1`. Ollama uses its local HTTP API.
The default local model is `qwen3:4b`; use `qwen3:1.7b` as the low-memory fallback for
OOM, unavailable-model, or fast smoke runs. The Gemini comparison model is
`gemini-3.5-flash`; the former 2.0 identifier was removed after that model was shut
down.

## Offline smoke run

```bash
python -m traceguard smoke
```

The smoke run uses the deterministic policy and offline heuristic supervisor. It does not require credentials, Ollama, AgentDojo, or Docker.

## Submission video demo

```bash
# concise live baseline-versus-hybrid comparison
python -m traceguard demo

# add a real Gemini task-agent and supervisor check
export GEMINI_API_KEY='your-rotated-key'
export GEMINI_BASE_URL='https://open.blackroute.space/v1'
python -m traceguard demo --gemini --gemini-base-url "$GEMINI_BASE_URL"
```

The command prints each proposed tool call, the supervisor decision, the execution
outcome, and utility/security checks. Full sanitized traces are saved under
`artifacts/`. Never put an API key in `.env.example`; use an ignored `.env` file or
export it in the recording shell.

## Experiments

```bash
# five cases per threat model across all eight ablations
python -m traceguard smoke-matrix --seed 0

# one case + one ablation
python -m traceguard experiment --split dev --case benign_math_dev --ablation A2

# full eight-ablation matrix on the development split
python -m traceguard experiment --split dev --seed 0

# held-out custom cases
python -m traceguard experiment --split test --seed 0

# Docker-applicable stratum with approved routes executed in containment
python -m traceguard experiment --split all --container --seed 0

# exploratory container run with post-run LLM/heuristic evidence reevaluation
python -m traceguard experiment --split all --container --post-run --seed 0

# frozen custom evaluation across both splits
python -m traceguard experiment --split all --seed 0

# regenerate summary.json and summary.csv from a completed run's sanitized traces
python -m traceguard analyze --run-dir artifacts/run_<timestamp>_0

# validate the AgentDojo install, version, suites, and selected task IDs
python -m traceguard agentdojo-info

# four-mode custom supervisor interface
python -m traceguard.run_ablation --suite custom --supervisor none --dry-run
python -m traceguard.run_ablation --suite custom --supervisor deterministic_llm --provider ollama

# AgentDojo smoke ablation with vulnerable-agent attack prompting
python -m traceguard.run_ablation \
  --suite agentdojo \
  --supervisor deterministic_llm \
  --agent-model qwen3:4b \
  --supervisor-model qwen3:4b \
  --agentdojo-suite workspace \
  --attack tool_knowledge \
  --dangerously-follow-tool-instructions \
  --smoke \
  --force-rerun

# conclusion matrix across none, deterministic, llm, and deterministic_llm
traceguard conclusion-ablation \
  --agent-model qwen3:4b \
  --supervisor-model qwen3:4b \
  --dangerously-follow-tool-instructions \
  --force-rerun
```

Camera-friendly Gemini ablation commands should use `tee` to save terminal output:

```bash
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=artifacts/conclusion_gemini_smoke_$TS
mkdir -p "$OUT"

stdbuf -oL -eL conda run -n traceguard-agentdojo env \
  PYTHONPATH=src:. PYTHONUNBUFFERED=1 \
  GEMINI_API_KEY="$GEMINI_API_KEY" \
  GEMINI_BASE_URL="${GEMINI_BASE_URL:-https://open.blackroute.space/v1}" \
  TRACEGUARD_GEMINI_TRANSPORT=auto \
  traceguard conclusion-ablation \
  --agent-provider gemini \
  --supervisor-provider gemini \
  --agent-model "${TRACEGUARD_GEMINI_MODEL:-gemini-3.5-flash}" \
  --supervisor-model "${TRACEGUARD_GEMINI_MODEL:-gemini-3.5-flash}" \
  --gemini-base-url "${GEMINI_BASE_URL:-https://open.blackroute.space/v1}" \
  --smoke \
  --camera-log-steps \
  --dangerously-follow-tool-instructions \
  --force-rerun \
  --output-dir "$OUT" 2>&1 | tee "$OUT/terminal.log"
```

Traces, manifests, CSV/JSON summaries, paired comparisons, and representative traces are
written under `artifacts/run_*`. Pairing keeps the same per-case seed across ablations.
Manifests record content digests for the cases and initial state. Persisted results redact
TraceGuard canaries, common secret assignments, and literal patterns configured through
`TRACEGUARD_REDACT_PATTERNS`.

`agentdojo-info` exits nonzero when AgentDojo is missing, its version differs from `0.1.35`,
or a configured suite/task ID is unavailable.

Conclusion ablations write `summary.csv`, `summary.json`, `conclusion_report.md`,
raw AgentDojo logs, and `traceguard_supervisor_calls.jsonl` under
`artifacts/conclusion_ablation_*`. Provider metadata in traces records the resolved
Ollama model tag, digest, quantization, resident bytes, and VRAM bytes when available.

## Repository layout

- `src/traceguard/supervisor/`: deterministic, Gemini, Ollama, and offline supervisors.
- `src/traceguard/sandbox/`: hardened Docker execution.
- `src/traceguard/tools/` and `src/traceguard/policy/`: typed tools and deterministic checks.
- `benchmarks/`: AgentDojo boundary, native runner helpers, and custom threat-model cases.
- `configs/`: eight primary ablations, four-mode smoke/full ablation configs, and sandbox profiles.
- `artifacts/`: ignored experiment output.

## Security boundary

`restricted_command` never invokes a host shell. Without an approved container plan it returns a simulated runtime marker. Container execution requires the trusted profile configuration to contain a pinned `@sha256:` digest and uses argv directly, without shell interpretation. The current prototype supports no-network container profiles; `restricted_network` remains declarative until an enforceable egress proxy is added.

Post-run reevaluation consumes bounded, untrusted sandbox evidence. It never automatically reruns a command on the host.

## Docker containment

The trusted [`configs/sandbox_profiles.json`](configs/sandbox_profiles.json) pins the
multi-architecture Python Alpine image by immutable digest and enables three profiles:

- `isolated_compute`: no network, host inputs, or persisted output.
- `readonly_input`: copies declared workspace inputs into temporary staging and mounts
  only that copy read-only.
- `artifact_build`: adds a fixed output mount, then rejects links, special files, excess
  file counts, and excess byte counts before copying artifacts under `artifacts/sandbox/`.

Limits and profile names come from this strict configuration; values on an execution
plan cannot add Docker flags or relax the configured limits. Every enabled profile uses
a non-root user, a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, no network or IPC namespace sharing, and fixed CPU, memory, PID,
timeout, and output limits. Container and staging cleanup runs on success, failure, and
timeout. If Docker, digest/architecture verification, artifact inspection, persistence,
or cleanup cannot be verified, execution fails closed and the runtime escalates.

On an ARM64 or amd64 Docker host, pull and verify the exact multi-architecture image:

```bash
docker pull python@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4
python -m traceguard sandbox-check
TRACEGUARD_RUN_DOCKER_TESTS=1 python -m pytest tests/sandbox -q
python -m traceguard sandbox-benchmark --runs 10
```

The benchmark writes code/config digests plus latency, peak-memory, writable-layer, and
cleanup measurements to `artifacts/sandbox_benchmark.json`. Docker Desktop still runs
containers inside its Linux VM; kernel/container escapes and compromise of the Docker
daemon remain outside this application-layer boundary. The Docker socket is never
mounted, but a daemon compromise would bypass these controls. Restricted network
execution stays disabled until destination enforcement through an egress proxy is
implemented.

## Benchmarking

AgentDojo is pinned to `0.1.35`. Custom cases in `benchmarks/cases/custom_cases.json` keep policy violations, direct attacks, and indirect injections distinct.

External suites use immutable manifests and ignored caches:

```bash
traceguard dataset list
traceguard dataset fetch llmail-inject
traceguard dataset verify llmail-inject
traceguard benchmark run --dataset llmail-inject --tier smoke
traceguard benchmark matrix --datasets toolsword r-judge asb-subset --tier smoke
```

Smoke tiers are harmless offline contract fixtures. Native standard/full runs require a
verified cache plus an executable JSON-protocol adapter supplied with
`--external-runner`. AgentDyn is sealed and additionally requires frozen
`--prompt-digest` and `--policy-digest` values for its full tier. Reports remain separate
per dataset and use equal-dataset weighting only for the optional macro summary.
