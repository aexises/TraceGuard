# Security contract and trust model

TraceGuard is an experimental security framework with a narrow supported execution
surface. It is not production-certified and does not implement an autonomous agent.
The application owns planning, trusted identity, approved tasks, handlers and credentials.

## Trusted boundary

Trust roots are application-authenticated principals and source identity, immutable task
grants, reviewed tool schemas/effect descriptors, the policy publisher, executor, and
verified deployment isolation. Model output, retrieved documents, tool results, memory,
claimed source labels and model explanations are untrusted data.

`SecuredTools` always selects strict grants and binds an application task ID. Its private
execution implementation has no agent loop or experiment switches, requires strict
application authority, and cannot disable deterministic enforcement. `SupervisionGateway`
requires explicit strict authority; its optional supervisor cannot bypass the compiled
kernel. Low-level policy annotations do not establish caller identity or authorize effects.

All mutating/command fields need exact, resource, authenticated-source or reviewed generated
field authority. Read selectors need schema-bound resource mappings. Changes to schemas,
effect descriptors, scopes or deployed adapters require reapproval. Models may withhold
more calls but cannot add permission; every rewrite passes the same checks again.

The control-plane API authenticates tenant/role scopes, applies explicit deny precedence,
records action-bound receipts and issues signed purpose-separated execution grants.
Authority mutations reload and authorize inside a durable transaction. Signed read-only
offline policy bundles retain a bounded stale-policy window and cannot authorize mutation.
See [execution grants](execution_grants.md) and [persistent authority](authority_storage.md).

## Supported profiles

| Profile | Implemented boundary | Material trust assumptions |
| --- | --- | --- |
| Embedded tools | Strict field/resource grants, confined filesystem, shared durable effect reservations, optional result review | Application code, handlers and host credentials remain trusted; arbitrary same-process code is not contained |
| Native Inspect | Reviewed read inventory and explicit guarded native dispatch, stable IDs, budgets, durable holds/results | The application exposes only the guarded route; raw callbacks and credentials must be isolated separately |
| Isolated reports | Non-root agent/issuer/executor separation, exact pinned mTLS identities, deployed adapter hash, quarantined public report publication | Single-host state, operator fencing/key custody, Docker and the target network perimeter remain trusted |
| Control plane | Tenant/role admission, signed bounded SQLite authority, review/grant/receipt/revocation state | Development API identity and Kubernetes templates are not a production identity or distributed state service |

Pending and unknown effects hold their task even after changed payloads, keys or process
restart. Missing, wrong or incompatible ledgers fail closed. Result acceptance is persisted
separately from execution: replay cannot expose withheld bytes or blindly redispatch an
uncertain effect. See [ledger lifecycle](ledger_lifecycle.md).

Artifacts become visible as complete committed bundles. Private bookkeeping cannot reverse
already-public truth. Separate gates apply to model-provider inputs, final answers and
artifact publication. The supported text/JSON classifier needs trusted source/application
labels; it is not general semantic DLP. See [data release](data_release.md).

## Limits and release criteria

This framework does not supply arbitrary-provider transactional guarantees, general secret
classification, causal taint tracking, KMS custody, distributed fencing, rollback detection
against a hostile storage operator, or replica-safe production state. Unsupported strict
adapters are withheld. A proxy/perimeter and target-host validation are required before
external exposure; local ingress limits are not Internet-scale denial-of-service protection.

[Verification coverage](verification.md) maps these contracts to maintained regressions.
Independent security review, held-out/adaptive efficacy evaluation, real application pilots,
owner license approval and operational deployment validation remain required for a supported
release. The [release evidence validator](release_assurance.md) must stay closed until
source-bound evidence exists. Passing local tests or scans does not establish those facts.
