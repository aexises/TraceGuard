# TraceGuard Setup Guide

This guide covers two supported uses of TraceGuard:

1. the local research runtime and benchmark suite; and
2. the v1 safety control-plane foundation for regulated agent and model actions.

The control plane is safe for local development with its bundled in-memory repository.
It is **not production-ready by itself**: production requires the persistence, identity,
key-management, evidence-storage, and queue adapters listed in
[Production readiness](#production-readiness).

## Requirements

- macOS, Linux, or a compatible container host.
- Python 3.11 or newer. Python 3.10 is unsupported because TraceGuard uses APIs added in
  Python 3.11.
- `git` and `pip`.
- Docker Desktop or Docker Engine only for sandbox checks and container execution.
- Kubernetes 1.27+ and a container registry only for cluster deployment.

Optional integrations:

- Gemini: a `GEMINI_API_KEY` environment variable and the `gemini` extra.
- AgentDojo: the `agentdojo` extra.
- External dataset evaluations: the `datasets` and/or `inspect` extras as required by the
 selected benchmark.

## Clone and install

```bash
git clone https://github.com/aexises/TraceGuard.git
cd TraceGuard

python3.11 -m pip install uv==0.13.1
uv lock --check
uv sync --locked --extra dev --no-install-project
uv sync --locked --extra dev --no-build-isolation --no-editable
source .venv/bin/activate
```

The first sync installs locked build tools before building the package. The second
uses those tools without an isolated, independently resolved build environment and
installs a regular wheel rather than an editable package.
Do not regenerate `uv.lock` during installation. The older `pip install -e '.[dev]'`
command remains usable for development but does not reproduce the release environment.

Install optional capabilities only when needed, retaining the same build-tools phase:

```bash
uv sync --locked --extra dev --extra gemini --no-install-project
uv sync --locked --extra dev --extra gemini --no-build-isolation --no-editable
# Substitute --extra agentdojo or --extra datasets --extra inspect as needed.
```

Do not commit virtual environments, API keys, generated experiment output, or secret files.
Set credentials in the shell or an ignored local secret-management file.

## Verify the installation

Run all checks with the project virtual environment active:

```bash
python -m pytest -q
ruff check .
ruff format --check .
python -m traceguard smoke
```

The smoke run is offline and requires neither Docker nor model-provider credentials. A
successful test run currently includes the control-plane contract tests in
`tests/test_control_plane.py`.

To exercise Docker containment, first ensure Docker is running, then use the pinned image
configured in `configs/sandbox_profiles.json`:

```bash
python -m traceguard sandbox-check
TRACEGUARD_RUN_DOCKER_TESTS=1 python -m pytest tests/sandbox -q
```

## Local research runtime

TraceGuard’s original runtime evaluates typed tool calls against deterministic policy and an
optional supervisor. It is useful for experiments, policy regression cases, and benchmarks.

```bash
# Deterministic offline run
python -m traceguard smoke

# Run the frozen custom development cases
python -m traceguard experiment --split dev --seed 0

# View available external dataset adapters
traceguard dataset list
```

Gemini use is opt-in. Never place the key in source control:

```bash
export GEMINI_API_KEY='...'
export GEMINI_BASE_URL='https://your-compatible-provider.example/v1'
python -m traceguard demo --gemini --gemini-base-url "$GEMINI_BASE_URL"
```

Refer to [External benchmark guidance](docs/external_benchmarks.md) for dataset
acquisition, cache verification, and native runner requirements.

## Research runtime operations

The following commands cover the experimental runtime described in the repository README.
Run them with the project virtual environment active.

### Offline smoke run

```bash
python -m traceguard smoke
```

The smoke run uses the deterministic policy and offline heuristic supervisor. It does not
require credentials, Ollama, AgentDojo, or Docker.

### Demo

```bash
# Concise live baseline-versus-hybrid comparison
python -m traceguard demo

# Add a Gemini task-agent and supervisor check
export GEMINI_API_KEY='your-rotated-key'
export GEMINI_BASE_URL='https://open.blackroute.space/v1'
python -m traceguard demo --gemini --gemini-base-url "$GEMINI_BASE_URL"
```

The command prints each proposed tool call, the supervisor decision, the execution outcome,
and utility and security checks. Sanitized traces are saved under `artifacts/`. Never put an
API key in `.env.example`; use an ignored `.env` file or export it in the recording shell.

### Experiments and ablations

```bash
# Five cases per threat model across all eight ablations
python -m traceguard smoke-matrix --seed 0

# One case and one ablation
python -m traceguard experiment --split dev --case benign_math_dev --ablation A2

# Full eight-ablation matrix on the development split
python -m traceguard experiment --split dev --seed 0

# Held-out custom cases
python -m traceguard experiment --split test --seed 0

# Docker-applicable stratum with approved routes executed in containment
python -m traceguard experiment --split all --container --seed 0

# Exploratory container run with post-run evidence reevaluation
python -m traceguard experiment --split all --container --post-run --seed 0

# Frozen custom evaluation across both splits
python -m traceguard experiment --split all --seed 0

# Regenerate summaries from a completed run's sanitized traces
python -m traceguard analyze --run-dir artifacts/run_<timestamp>_0

# Validate AgentDojo installation, version, suites, and selected task IDs
python -m traceguard agentdojo-info

# Four-mode custom supervisor interface
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

# Conclusion matrix across none, deterministic, LLM, and deterministic-LLM modes
traceguard conclusion-ablation \
  --agent-model qwen3:4b \
  --supervisor-model qwen3:4b \
  --dangerously-follow-tool-instructions \
  --force-rerun
```

For a camera-friendly Gemini ablation run that saves terminal output:

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

Traces, manifests, CSV and JSON summaries, paired comparisons, and representative traces are
written under `artifacts/run_*`. Pairing keeps the same per-case seed across ablations.
Manifests record content digests for cases and initial state. Persisted results redact
TraceGuard canaries, common secret assignments, and literal patterns configured through
`TRACEGUARD_REDACT_PATTERNS`.

`agentdojo-info` exits nonzero when AgentDojo is missing, its version differs from `0.1.35`,
or a configured suite or task ID is unavailable. Conclusion ablations write `summary.csv`,
`summary.json`, `conclusion_report.md`, raw AgentDojo logs, and
`traceguard_supervisor_calls.jsonl` under `artifacts/conclusion_ablation_*`. Provider metadata
in traces records the resolved Ollama model tag, digest, quantization, resident bytes, and VRAM
bytes when available.

### Docker containment

The trusted [sandbox profile configuration](configs/sandbox_profiles.json) pins the
multi-architecture Python Alpine image by immutable digest and enables three profiles:

- `isolated_compute`: no network, host inputs, or persisted output.
- `readonly_input`: copies declared workspace inputs into temporary staging and mounts only that
  copy read-only.
- `artifact_build`: adds a fixed output mount, then rejects links, special files, excess file
  counts, and excess byte counts before copying artifacts under `artifacts/sandbox/`.

Limits and profile names come from this strict configuration; execution plans cannot add Docker
flags or relax configured limits. Enabled profiles use a non-root user, a read-only root
filesystem, dropped capabilities, `no-new-privileges`, no network or IPC namespace sharing, and
fixed CPU, memory, PID, timeout, and output limits. Cleanup runs after success, failure, and
timeout. If Docker, image or architecture verification, artifact inspection, persistence, or
cleanup cannot be verified, execution fails closed.

On an ARM64 or amd64 Docker host, pull and verify the exact multi-architecture image:

```bash
docker pull python@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4
python -m traceguard sandbox-check
TRACEGUARD_RUN_DOCKER_TESTS=1 python -m pytest tests/sandbox -q
python -m traceguard sandbox-benchmark --runs 10
```

The benchmark writes code and configuration digests plus latency, peak-memory,
writable-layer, and cleanup measurements to `artifacts/sandbox_benchmark.json`. Docker Desktop
runs containers in its Linux VM; kernel and container escapes or Docker-daemon compromise remain
outside this application-layer boundary. The Docker socket is never mounted. Restricted network
execution stays disabled until destination enforcement through an egress proxy is implemented.

### External benchmarks

AgentDojo is pinned to `0.1.35`. Custom cases in `benchmarks/cases/custom_cases.json` keep
policy violations, direct attacks, and indirect injections distinct.

External suites use immutable manifests and ignored caches:

```bash
traceguard dataset list
traceguard dataset fetch llmail-inject
traceguard dataset verify llmail-inject
traceguard benchmark run --dataset llmail-inject --tier smoke
traceguard benchmark matrix --datasets toolsword r-judge asb-subset --tier smoke
```

Smoke tiers are harmless offline contract fixtures. Native standard and full runs require a
verified cache plus an executable JSON-protocol adapter supplied with `--external-runner`.
AgentDyn is sealed and additionally requires frozen `--prompt-digest` and `--policy-digest`
values for its full tier. Reports remain separate per dataset and use equal-dataset weighting
only for the optional macro summary.

## Control-plane architecture

The control plane exposes a versioned HTTP boundary for:

| Capability | Endpoint / component |
| --- | --- |
| Agent action evaluation | `POST /v1/actions/evaluate` |
| Signed offline policy cache | `GET /v1/policies/bundle` |
| Policy lifecycle | `/v1/policies/*` |
| Human review resolution | `POST /v1/reviews/{review_id}/resolve` |
| Tamper-evident audit export | `GET /v1/audit/export` |
| Model policy gate | `POST /v1/chat/completions` |
| Customer-side enforcement | `traceguard.sdk.TraceGuardClient` |

An action is allowed only by an active policy rule. Unknown actions, missing policies,
expired/tampered caches, and unavailable control planes without an eligible cached rule are
blocked. `ESCALATE` creates a review record that expires after 24 hours; it never authorizes
execution until a reviewer resolves it.

## Run the development API

Install the normal package dependencies, then generate a dedicated local signing key:

```bash
export TRACEGUARD_SIGNING_KEY="$(openssl rand -hex 32)"
export TRACEGUARD_DEV_TOKEN="$(openssl rand -hex 32)"
export TRACEGUARD_ALLOW_IN_MEMORY=1
traceguard-api
```

The API binds to port 8080 (all interfaces by default). Check health locally:

```bash
curl http://127.0.0.1:8080/healthz
```

The bundled development application recognizes one agent token only. It intentionally cannot
create or approve policies because that would encourage deployment with a static development
identity. For local integration tests, construct `ControlPlane` and `create_app` with an
identity resolver that maps separate test tokens to `admin`, `approver`, `reviewer`, and
`auditor` actors. In production, replace `token_resolver` with an OIDC-verifying identity
adapter; never trust identity headers supplied by an untrusted client.

### Create and activate a policy

Policies follow a four-eyes workflow:

1. An `admin` creates a draft.
2. The author submits the draft.
3. A different `approver` activates it.
4. The active policy is issued as a signed tenant-scoped bundle to authenticated agents.

Rules match action kind, operation, destination prefix, selected arguments, and whether
untrusted evidence contains instructions. Rules are processed by descending priority. A
`REWRITE` rule must include replacement arguments. Only `ALLOW` rules can set
`cache_eligible: true`.

Example draft body:

```json
{
  "name": "tenant-default",
  "default_decision": "BLOCK",
  "rules": [
    {
      "name": "allow inventory GET",
      "priority": 100,
      "match": {
        "kind": "http",
        "operation": "GET",
        "target_prefix": "https://inventory.example.com/"
      },
      "decision": "ALLOW",
      "reason": "approved inventory read",
      "cache_eligible": true
    },
    {
      "name": "review untrusted instructions",
      "priority": 1000,
      "match": {"contains_untrusted_instructions": true},
      "decision": "ESCALATE",
      "reason": "untrusted instructions require human review"
    }
  ]
}
```

Use an `Idempotency-Key` per logical action. Retrying the same action with the same tenant and
key returns the original decision and audit reference rather than creating another side effect.

### Evaluate an action

Send authenticated requests through the API. The request identity must contain the `agent`
role and a scoped service credential:

```bash
curl -X POST http://127.0.0.1:8080/v1/actions/evaluate \
  -H 'Authorization: Bearer <AGENT_SERVICE_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "tenant-a",
    "idempotency_key": "order-9340-send-1",
    "kind": "http",
    "operation": "POST",
    "target": "https://api.example.com/orders",
    "arguments": {"body_class": "order"},
    "provenance": ["model-output-123"]
  }'
```

The response includes the decision, reason, policy reference, audit ID, optional rewritten
arguments, and optional review ID. Execute the external action only after receiving `ALLOW`.
Treat `BLOCK`, `ESCALATE`, and `REWRITE` as non-authorization until the caller has applied the
corresponding safe workflow.

### Model traffic

`POST /v1/chat/completions` accepts OpenAI-style request payloads and evaluates them as a
`model_request`. It redacts common secret-assignment patterns in stored evidence. The current
endpoint is deliberately a policy gate and returns `501` after an allowed decision unless a
provider-specific upstream adapter is supplied. It does not silently forward model traffic.

## SDK integration

Use `TraceGuardClient` at every mediated side-effect boundary. The `request_http` helper first
obtains a control-plane decision and only sends the HTTP request after `ALLOW`.

```python
from traceguard.control.models import HttpAction
from traceguard.sdk import TraceGuardClient

client = TraceGuardClient(
    base_url="https://traceguard.example.com",
    bearer_token="agent-service-token",
)

response_bytes = client.request_http(
    tenant_id="tenant-a",
    idempotency_key="inventory-read-42",
    request=HttpAction(method="GET", url="https://inventory.example.com/items"),
)
```

For outage resilience, retrieve a signed bundle while the control plane is available and install
it in `SignedPolicyCache`. The cache verifies the HMAC signature and expiration before use. It
may authorize only a matching rule that is both `ALLOW` and `cache_eligible`; all other offline
requests fail closed. Cached decisions are retained by the client for reconciliation after the
control plane returns.

Do not use this SDK as a transparent egress proxy. It governs only calls made through its
mediated client. Enforce uninstrumented workload egress separately at the network layer.

## Kubernetes deployment

The starter manifest is `deploy/kubernetes/control-plane.yaml`. It is a disposable,
single-replica development deployment with a `Recreate` strategy. Its in-memory state
is lost on restart; scaling it is unsupported. Do not expose it to production traffic.

Follow [Container build and release checks](docs/control_plane.md#container-build-and-release-checks)
to build with a local tag, verify the published image digest, generate a manifest with
`release-validate --output-manifest`, and validate its Kubernetes schema. Do not apply
the checked-in placeholder or use an image digest as a build tag.

Create dedicated credentials for a non-production cluster, then apply only the generated
manifest after completing those checks:

```bash
kubectl create namespace traceguard
kubectl -n traceguard create secret generic traceguard-secrets \
  --from-literal=signing-key="$(openssl rand -hex 32)" \
  --from-literal=agent-token="$(openssl rand -hex 32)"
kubectl -n traceguard apply -f artifacts/release/control-plane.yaml
kubectl -n traceguard rollout status deployment/traceguard-api
```

The manifest retains non-root execution, a read-only filesystem, dropped capabilities,
resource limits and health probes. It does not supply persistence, OIDC, ingress, TLS,
NetworkPolicies, a queue or backups. Production requires replacing the bundled API
factory and in-memory stores; changing the replica count does not provide durability.

## Production readiness

Do not process production traffic until all of the following are implemented and reviewed:

- **Persistence:** Replace the in-memory policy, review, idempotency, and audit stores with
  tenant-isolated PostgreSQL repositories using transactions and durable migrations.
- **Audit integrity:** Persist hash-chain events append-only, create periodic externally stored
  signed checkpoints, verify chains during export, and test backup/restore.
- **Evidence:** Store encrypted, time-limited full evidence in an approved object store; retain
  only metadata and redacted excerpts by default. Enforce tenant-scoped access and deletion.
- **Keys:** Replace the development HMAC key with KMS/HSM-backed signing and envelope encryption,
  key IDs, rotation, revocation, and audit logging.
- **Identity:** Validate OIDC issuer, audience, signature, expiry, and group-to-role mappings.
  Issue scoped, rotatable service credentials to agents; never use the development token resolver.
- **Queue and reviews:** Persist review jobs, retries, dead-letter handling, reviewer notification,
  24-hour expiry handling, and an auditable reviewer UI/workflow.
- **Model providers:** Implement explicit provider adapters with timeouts, response redaction,
  streaming behavior, and provider credential isolation.
- **Operations:** Add rate limiting, distributed tracing, metrics, alerting, log redaction,
  database/object-store/KMS failure tests, DR exercises, vulnerability scanning, SBOM/provenance,
  and signed immutable container releases.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| `ImportError: cannot import name UTC from datetime` | Use Python 3.11+ and recreate `.venv`. |
| API returns `401` | Supply a valid bearer credential recognized by the configured identity resolver. |
| API returns `BLOCK` with `no active policy` | Create, submit, and have a separate approver activate a tenant policy. |
| SDK raises `PolicyUnavailable` | Restore control-plane connectivity or install a valid unexpired bundle containing a matching cache-eligible allow rule. |
| Model endpoint returns `501` | Configure and deploy an explicit upstream provider adapter; forwarding is intentionally disabled by default. |
| Kubernetes pod does not start | Confirm the image digest, `traceguard-secrets/signing-key`, image-pull access, and the container’s port 8080 health endpoint. |

## Security reminders

- Never put API keys, signing keys, bearer tokens, or customer evidence in Git.
- Treat model output, retrieved documents, tool responses, and memory entries as untrusted unless
  their provenance proves otherwise.
- Do not treat a sandboxed command or cached decision as permission to bypass the policy service.
- Test policy changes against golden cases before approval and keep a rollback-ready prior policy.
- Use separate tenants, service credentials, encryption contexts, and audit chains for every
  customer organization.
