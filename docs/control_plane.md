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

Kubernetes manifests use a non-root, read-only container with dropped capabilities. Replace
the placeholder release image digest and provide `traceguard-secrets/signing-key` through
your secret manager. The Dockerfile's base image must likewise be supplied as an immutable
digest by release automation.
