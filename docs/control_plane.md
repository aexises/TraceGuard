# TraceGuard control plane

The v1 control plane exposes `/v1/actions/evaluate`, signed policy bundles, policy
lifecycle endpoints, review resolution, audit export, and an OpenAI-compatible
`/v1/chat/completions` policy gate. It fails closed when no active policy exists.

`ControlPlane` currently ships with an in-memory repository for development and tests.
Production deployers must supply transactional PostgreSQL persistence, an object-store
evidence adapter, KMS-backed signing/encryption, a queue worker, and an OIDC identity
resolver before handling production traffic. The included `token_resolver` is a test and
development adapter only; it is not an OIDC implementation.

The SDK can fall back only to a valid Ed25519-signed cached policy bundle and only for rules
explicitly marked `cache_eligible`. Escalations, blocks, expired bundles, unknown actions,
and control-plane outages without a qualifying cached rule all remain blocked.

The bundled API and Kubernetes manifest are development-only. The process owns all
policy, review, idempotency and audit state in memory. Restarting loses it. The manifest
uses one replica and `Recreate` updates to avoid overlapping independent stores; this
also means updates have downtime. Do not scale this backend or describe it as durable.
Production requires a separate application factory with persistent shared adapters.

The API refuses to start unless `TRACEGUARD_ALLOW_IN_MEMORY=1` is explicitly set, and
requires a dedicated signing key and agent token of at least 32 bytes/characters.
There are no default credentials. Kubernetes loads both credentials from
`traceguard-secrets` (`signing-key` and `agent-token`). The agent token cannot administer
policies. A successful `/healthz` checks process health, not production readiness.

## Container build and release checks

Use uv 0.13.1 for the lock-based setup described in `setup.md`. Docker installs the
build tools from `uv.lock`, builds without dependency isolation, and installs runtime
dependencies from a hashed export of that lock. It copies all packages and bundled
configurations. The runtime image does not include the build environment or uv.
The pinned uv bootstrap itself is outside the project lock.

Set `PYTHON_IMAGE` to a verified immutable Python 3.11+ image reference. CI uses the
same multi-architecture base digest as the sandbox configuration. Validate registry
availability before building. A local build tag is distinct from the published digest:

```bash
export PYTHON_IMAGE='python@sha256:<verified base-image digest>'
export TRACEGUARD_TAG='<registry>/<repository>:<release-tag>'
docker buildx imagetools inspect "$PYTHON_IMAGE"
docker build --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" --tag "$TRACEGUARD_TAG" .
```

Publish only through your approved release process. Obtain the **registry manifest**
digest from that publication (not the local Docker image/config ID), then:

```bash
export TRACEGUARD_IMAGE='<registry>/<repository>@sha256:<published manifest digest>'
docker buildx imagetools inspect "$TRACEGUARD_IMAGE"
python -m traceguard release-validate \
  --base-image "$PYTHON_IMAGE" --release-image "$TRACEGUARD_IMAGE" \
  --output-manifest artifacts/release/control-plane.yaml
kubeconform -strict -summary -kubernetes-version 1.27.0 artifacts/release/control-plane.yaml
```

`release-validate` checks image-reference syntax and Docker base-image inputs. With
`--output-manifest`, it writes a new manifest containing the full immutable image
reference; it never modifies the template or overwrites an existing artifact. Choose
a fresh output path for every attempt. Without that option, it only checks inputs.
It does **not** verify registry existence, signatures, Kubernetes schemas, or production
adapters; the registry and kubeconform commands above are separate required gates.
CI's schema check uses a synthetic image reference and does not prove registry availability.

Only apply the generated manifest after all gates pass and the two secrets exist:

```bash
kubectl -n traceguard apply -f artifacts/release/control-plane.yaml
```

The existing non-root user, read-only filesystem, dropped capabilities, disabled
service-account-token mount, and runtime-default seccomp profile remain required.
This command deploys a disposable development service, not a production control plane.


## Principal scope

Identity adapters must supply explicit `Actor.tenant_ids`; an empty set grants no tenant access.
Every public service operation checks tenant membership and role before accessing state.
Agent credentials may additionally constrain `allowed_operations`. Resource access remains
bounded by the tenant's active policy; membership alone never supplies an ALLOW.
The development token belongs only to `TRACEGUARD_DEV_TENANT` (default `tenant-a`).
Do not obtain principal scopes from an action body, model output or evidence labels.


Idempotency receipts are bound to tenant, principal, credential, task and canonical action.
Changed payload reuse returns HTTP 409. Policy activation/rollback or receipt expiry also
requires a new key; a cached ALLOW never authorizes work under a changed policy. Transport
request timestamps/action IDs are not semantic payload. Responses include `action_digest`.
These are decision receipts, not proof of execution or an exactly-once side-effect guarantee.
The development store serializes policy/decision updates within one process only.


## Public HTTP execution profile

HTTP target rules now compare parsed origins (scheme, host and effective port), path
segment boundaries and exact query strings. Userinfo, fragments, path traversal/encoded
aliases, control characters and ambiguous authority forms are denied. A query omitted
from a scope grants no arbitrary query parameters. Non-HTTP legacy target prefixes are
not advertised as filesystem/object authorization.

`TraceGuardClient.request_http` defaults to public HTTPS transport: DNS answers must all
be public, the socket uses a validated IP while TLS authenticates the original hostname,
proxy environment variables are ignored, response bytes are bounded and redirects are
rejected. A new destination must be explicitly evaluated. Unsafe Host/framing headers
cannot replace the evaluated authority. Network tests use fake DNS/connections, not
external sites; live public-service integration remains a separate release gate.


## Offline grants and audit-v2 migration

The cache accepts a pinned Ed25519 **public verification key**, tenant, audience, service
credential ID and key ID. It receives no signing secret. Bundles have at most five minutes
of validity, carry a monotonically checked activation epoch and can authorize only explicit
HTTP GET/HEAD rules. Auth/authorization/schema/throttle HTTP errors and TLS failures never
trigger fallback. Offline policy revocation can still lag until expiry; do not use offline
grants for consequential effects. Reconciliation keeps unacknowledged decisions on failure;
it reconciles decisions, not proof that an external effect actually occurred.

Policy and audit keys are purpose-separated. The development backend derives them from
the configured high-entropy seed; KMS/rotation and durable revocation remain release work.
Audit-v2 hashes event ID, timestamp, sequence and complete canonical event metadata. Export
verifies the chain and signs its count/head with the separate audit identity. Process-local
head checks detect local corruption/truncation, but independent durable checkpoints and
storage access control remain necessary for production tamper evidence.

Example cache configuration in application-owned code:

```python
cache = SignedPolicyCache(
    policy_public_key, tenant_id="tenant-a", audience="agent",
    service_key_id="key-1", key_id="development-ed25519-v1",
)
```

Obtain/pin `policy_public_key` through trusted deployment configuration, not the same
unauthenticated response carrying the bundle. Recreate the cache with approved keys and a
trusted minimum epoch during rotation. A valid signature does not authenticate arbitrary
retrieved evidence or attest to tool correctness.
