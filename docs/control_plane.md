# TraceGuard control plane

The v1 control plane exposes `/v1/actions/evaluate`, signed policy bundles, policy
lifecycle endpoints, review resolution, audit export, and an OpenAI-compatible
`/v1/chat/completions` policy gate. It fails closed when no active policy exists.

`ControlPlane` currently ships with an in-memory repository for development and tests.
Production deployers must supply transactional PostgreSQL persistence, an object-store
evidence adapter, KMS-backed signing/encryption, a queue worker, and an OIDC identity
resolver before handling production traffic. The included `token_resolver` is a test and
development adapter only; it is not an OIDC implementation.

The SDK can fall back only to a valid HMAC-signed cached policy bundle and only for rules
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
