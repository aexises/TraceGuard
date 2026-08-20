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
git clone <YOUR_TRACEGUARD_REPOSITORY_URL>
cd AAI-project

python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

Install optional capabilities only when needed:

```bash
python -m pip install -e '.[dev,gemini]'
python -m pip install -e '.[dev,agentdojo]'
python -m pip install -e '.[dev,datasets,inspect]'
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

Refer to `README.md` for benchmark commands and `docs/external_benchmarks.md` for dataset
acquisition, cache verification, and native runner requirements.

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
export TRACEGUARD_DEV_TOKEN="replace-this-development-token"
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

The starter manifest is `deploy/kubernetes/control-plane.yaml`. Before applying it:

1. Build an image from `Dockerfile` using a Python base image pinned by immutable digest.
2. Push it to your approved registry and replace `REPLACE_WITH_RELEASE_DIGEST` with that digest.
3. Store a high-entropy signing key in your cloud secret manager and synchronize it into the
   `traceguard-secrets` Kubernetes secret as `signing-key`.
4. Configure TLS ingress, NetworkPolicies, resource quotas, backups, and pod-disruption budget
   according to your cluster standard.
5. Replace the in-memory control-plane adapters before exposing the service.

Example secret creation for a non-production cluster:

```bash
kubectl create namespace traceguard
kubectl -n traceguard create secret generic traceguard-secrets \
  --from-literal=signing-key="$(openssl rand -hex 32)"
kubectl -n traceguard apply -f deploy/kubernetes/control-plane.yaml
kubectl -n traceguard rollout status deployment/traceguard-api
```

The manifest runs as a non-root user with a read-only root filesystem, dropped Linux
capabilities, disabled service-account token mounting, resource limits, and health probes.
It does not create a database, ingress, TLS certificate, queue, or storage bucket.

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
