# External benchmark datasets

TraceGuard integrates external suites through pinned manifests and hybrid adapters. It
supervises calls, preserves provenance, redacts artifacts, and normalizes reporting while
leaving native environments, tools, and authoritative checkers in their upstream
runtimes. Tiny synthetic fixtures make the adapter contracts testable offline; they are
not substitutes for native standard or full scores.

## Inventory and scope

| Dataset | Scope | Runtime | License in manifest |
|---|---|---|---|
| ToolSword | Offline supervisor diagnostic | TraceGuard fixture/import adapter | Apache-2.0 |
| R-Judge | Offline risk-judgment diagnostic | TraceGuard fixture/import adapter | NOASSERTION; review upstream terms |
| LLMail-Inject | Email retrieval and indirect injection | Synthetic per-case mailbox/outbox | MIT |
| AgentDyn | Sealed Shopping, GitHub, and Daily Life holdout | Separate pinned native environment | MIT |
| InjecAgent | Tool-output injection and virtual effects | Replayed schemas and synthetic state | MIT |
| AgentHarm | Direct harmful multi-step tasks | Pinned Inspect/Inspect Evals environment | MIT |
| ASB subset | Memory poisoning and observation injection only | Disposable memory and fixture tools | MIT |

Repository URLs, immutable commits, required paths, fixture hashes, tier sizes, and
holdout status live in `benchmarks/datasets/manifests/`. Upstream files are fetched into
the ignored `.cache/traceguard-datasets/` directory. Review each upstream license before
redistributing cached content.

## Setup and data lifecycle

Use Python 3.11 or newer and install from the lockfile:

```bash
uv sync --extra dev --extra datasets
traceguard dataset list
traceguard dataset fetch llmail-inject
traceguard dataset verify llmail-inject
```

`fetch` clones only the manifest's immutable revision. `verify` checks the checkout
revision, required paths, and committed fixture hash. Network access is allowed only
during this acquisition step. Cache size and download duration depend on upstream
history and data assets; inspect free disk space before fetching all seven sources.

Native environments are independently locked:

```bash
uv sync --project benchmarks/environments/agentdyn
uv sync --project benchmarks/environments/inspect
```

The benchmark request records the SHA-256 of the relevant `uv.lock`. AgentDyn runs use
its own environment because its AgentDojo fork conflicts with TraceGuard's pinned
AgentDojo. The executable supplied with `--external-runner` must implement the strict
versioned JSON stdin/stdout contract in `benchmarks/datasets/protocol.py`.

## Running evaluations

```bash
# Offline contract fixtures: no network, credentials, or host tool execution
traceguard benchmark run --dataset toolsword --tier smoke
traceguard benchmark matrix \
  --datasets r-judge llmail-inject injecagent agentharm asb-subset \
  --tier smoke

# Native evaluation after fetch and environment setup
traceguard benchmark run \
  --dataset agentharm \
  --tier standard \
  --external-runner /absolute/path/to/inspect-adapter

# Sealed AgentDyn: freeze prompt and policy before the one full evaluation
traceguard benchmark run \
  --dataset agentdyn \
  --tier full \
  --prompt-digest <sha256> \
  --policy-digest <sha256> \
  --external-runner /absolute/path/to/agentdyn-adapter
```

AgentDyn intentionally has no standard/development tier. Do not inspect individual
holdout cases or tune policies after freezing hashes. Default reports retain redacted
case results locally but interpret the holdout through aggregate metrics.

Each run writes a redacted JSONL, an experiment manifest, and a summary beneath
`artifacts/dataset_benchmark_*`. Results are reported separately per dataset. The optional
macro summary weights datasets equally, so LLMail's larger sample count cannot dominate
the other suites. Diagnostic accuracy/F1 belongs in diagnostic reports and must not be
described as attack-prevention performance.

## Tools and side-effect boundary

Fixture tools include email search/list/read/send, synthetic service calls, untrusted
observations, and seeded memory create/replace/insert/delete/rename operations. Email
sends append only to the current case's outbox. GitHub, shopping, payment, calendar, and
harmful actions are virtual effects in disposable state.

The strict native factory exposes only reviewed `read_file`, `list_files` and `grep`
resource mappings. Native bash, Python, text editor and memory are unavailable in the
strict standard-tool profile. Explicit `profile="research"` exposes the broader maintained
tool inventory, including bounded single-command `bash`, for labelled research only.
Consequential native tools require the guarded solver route in `inspect_execution.md`;
approval alone cannot account for dispatch. Terminal capability is enabled only for cases declaring it. Model
providers run outside the container, and provider credentials are never included in the
tool environment.

The Inspect container contract pins an image digest and requires no network, a read-only
root, non-root UID, all capabilities dropped, no-new-privileges, bounded CPU/RAM/PIDs,
and a no-exec tmpfs. Inputs must be copied to temporary staging and mounted read-only;
the live repository, Docker socket, SSH agent, home directory, and credentials must
never be mounted. Only allowlisted regular artifacts may escape after path, symlink,
type, count, and size validation.

Before any terminal-backed evaluation, run:

```bash
python -m traceguard sandbox-check
TRACEGUARD_RUN_DOCKER_TESTS=1 python -m pytest tests/sandbox -q
```

Missing Docker, a digest or architecture mismatch, failed canary, cleanup failure, or
incomplete containment evidence aborts execution. Benchmark containers cannot install
packages or download content.

## CI and interpretation

- Unit CI validates manifests, adapters, predicates, provenance, redaction, virtual
  state, split leakage, and fixture-only episodes.
- Smoke uses two benign and two adversarial fixtures per integrated dataset.
- Standard/manual runs frozen representative native selections with the local Qwen
  model.
- Full/manual runs complete configured suites and repetitions, including AgentDyn only
  after the freeze.

LLMail participant IDs and normalized MinHash payload families must be disjoint between
development and test selections. Every adversarial case needs an executable
utility/security checker and an authorized near-neighbor. ASB v1 is restricted to the
reviewed memory-poisoning and observation-injection subset; mixed attacks, backdoors, and
the full AIOS runtime are explicitly out of scope.
