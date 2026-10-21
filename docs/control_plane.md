# Control-plane API and deployment

The control plane manages tenant policy, reviews, decision receipts, audit exports
and signed execution grants. It denies action requests without an active policy.
A policy decision does not itself execute a tool or prove that an effect occurred.

## Choose the state and identity profile

| Profile | State | Intended use |
| --- | --- | --- |
| Bundled `traceguard-api` / `_development_app` | In-memory `ControlPlane`; all state is lost on restart | Disposable development and API tests |
| Application factory with `SQLiteControlPlane` | Signed, transactional, bounded local SQLite snapshot | Durable single-host authority with trusted key custody and fenced recovery |
| Distributed service | No supplied shared-state/identity implementation | Requires separate implementation and operational validation |

`create_app(control, identity)` accepts the configured control plane and identity
resolver. The bundled token resolver is a development adapter, not OIDC. Applications
must authenticate actors and supply tenant membership, roles and service credentials
from a trusted identity source. [Authority storage](authority_storage.md) describes
persistence and offline rotation; do not infer distributed safety from local SQLite.

The development factory requires `TRACEGUARD_ALLOW_IN_MEMORY=1`, a dedicated signing
key of at least 32 bytes and an agent token of at least 32 characters. There are no
default credentials. Its token is an AGENT for `TRACEGUARD_DEV_TENANT` (default
`tenant-a`) and cannot administer policy. Follow [setup](../setup.md#5-run-a-local-control-plane-service)
for a loopback-only launch. `/healthz` checks process health, not deployment readiness.

## API responsibilities

| Surface | Responsibility |
| --- | --- |
| `/v1/actions/evaluate` | Evaluate a typed action under active tenant policy and return an action-bound decision receipt |
| Policy lifecycle and bundle endpoints | Draft, submit, approve, roll back and distribute signed policy within role scope |
| Review resolution | Bind a review decision to the original action and authority context |
| `/v1/tasks/register` | Register immutable strict task authority through authenticated administration |
| `/v1/execution/grants`, `/v1/execution/validate` | Issue short-lived signed grants and check current authority for an executor |
| `/v1/audit/export` | Verify and sign the exported audit chain |
| `/v1/chat/completions` | Evaluate a model request; return 403 on denial or 501 after ALLOW because no upstream forwarding adapter is configured |

The chat-compatible route is a policy gate, not a working general model proxy.
Use the [execution-grant contract](execution_grants.md) for actual executor integration.

## Principal scope and idempotency

Identity adapters must provide explicit `Actor.tenant_ids`; an empty set grants no tenant
access. Public operations check tenant membership and role before state access. Agent
credentials can further constrain `allowed_operations`. Membership alone does not grant
an action: active policy and registered strict authority still apply. Never derive
principal scope from a request body, model output or evidence label.

Decision receipts bind tenant, principal, credential, task and canonical action. Reusing
an idempotency key with changed payload returns HTTP 409. Receipt expiry or policy
activation/rollback requires a new key; a cached ALLOW cannot authorize changed policy.
Transport timestamps/action IDs are not semantic payload. Responses include
`action_digest`. These are decision receipts, not exactly-once side-effect receipts.
The development store serializes updates only within one process.

## Public HTTP execution

`TraceGuardClient.request_http` defaults to public HTTPS. Authorization compares parsed
origins (scheme, host, effective port), path segment boundaries and exact query strings.
An omitted query does not allow arbitrary parameters. Userinfo, fragments, traversal,
encoded aliases, control characters and ambiguous authority forms are denied.
Non-HTTP legacy prefixes do not establish filesystem or object authorization.

The transport requires all DNS answers to be public, connects to a validated IP and
checks TLS against the original hostname. It ignores proxy environment variables,
bounds response bytes and rejects redirects. New destinations need fresh evaluation;
Host/framing headers cannot replace the approved authority. Tests use fake DNS and
connections, not live public services. Validate the real provider separately.

## Offline read policies and audit integrity

`SignedPolicyCache` accepts a pinned Ed25519 public verification key, tenant, audience,
service credential ID and key ID. It receives no signing secret. Bundles last at most
five minutes and carry a checked activation epoch. Only explicit `cache_eligible`
HTTP GET/HEAD rules can authorize offline work.

BLOCK, ESCALATE, unknown actions, expired bundles, authorization/schema/throttle errors
and TLS failures do not become offline ALLOW. Outage fallback needs a valid qualifying
bundle. Revocation can lag until expiry, so this route cannot authorize consequential
effects. Reconciliation retains unacknowledged decisions on failure; it does not prove
that a provider executed an action.

Example configuration in trusted application code:

```python
from traceguard.sdk import SignedPolicyCache

cache = SignedPolicyCache(
    policy_public_key,
    tenant_id="tenant-a",
    audience="agent",
    service_key_id="key-1",
    key_id="development-ed25519-v1",
)
```

Obtain `policy_public_key` through trusted deployment configuration, independently of the
bundle response. During rotation, recreate verifiers with approved keys and a trusted
minimum epoch. A policy signature does not authenticate retrieved content or handlers.

Policy, execution and audit signing purposes are separated. Audit-v2 hashes event ID,
timestamp, sequence and complete canonical metadata; export verifies the chain and signs
its count/head. Local head checks detect local corruption/truncation. Independently
protected checkpoints and storage controls remain necessary against hostile rollback.
The [persistent profile](authority_storage.md) supports durable revocation and offline
rekeying; KMS custody and online/distributed rotation are not supplied.

## Build and validate deployment artifacts

Use the locked build in [setup](../setup.md). Docker installs locked build tools, builds
without dependency isolation and installs runtime dependencies from a hashed lock export.
The runtime omits uv and the build environment. The pinned uv bootstrap is outside the
project lock. Choose and verify an immutable base before building:

```bash
export PYTHON_IMAGE='python@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4'
export TRACEGUARD_TAG='<registry>/<repository>:<candidate-tag>'
docker buildx imagetools inspect "$PYTHON_IMAGE"
docker build --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" --tag "$TRACEGUARD_TAG" .
```

Publish only through an approved process. Obtain the published **registry manifest**
digest, not a local Docker config/image ID, then validate a fresh output path:

```bash
export TRACEGUARD_IMAGE='<registry>/<repository>@sha256:<published-manifest-digest>'
docker buildx imagetools inspect "$TRACEGUARD_IMAGE"
traceguard release-validate \
  --base-image "$PYTHON_IMAGE" --release-image "$TRACEGUARD_IMAGE" \
  --output-manifest artifacts/release/control-plane.yaml
kubeconform -strict -summary -kubernetes-version 1.27.0 artifacts/release/control-plane.yaml
```

`release-validate` checks reference syntax and Docker base inputs. It does not check
registry existence, signatures, Kubernetes schemas or application adapters. Rendering
never overwrites an existing output. The registry and schema checks are separate gates;
CI's synthetic reference proves only schema validity, not registry availability.

The Kubernetes template is a one-replica in-memory development service with `Recreate`
updates and downtime. Never scale it as a shared authority. Before applying a generated
manifest, all candidate gates must pass and `traceguard-secrets` must contain dedicated
`signing-key` and `agent-token` entries in the namespace:

```bash
kubectl -n traceguard apply -f artifacts/release/control-plane.yaml
```

Preserve non-root execution, read-only root, dropped capabilities, disabled service
account token mount and runtime-default seccomp. This remains a development deployment.
Target identity, key custody, persistence, fencing, transport perimeter and recovery need
separate validation before any supported production service.
