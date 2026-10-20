Action-bound execution and human review
======================================

The development control plane now exposes task registration, signed execution grants
and executor validation. These provide the authorization/reservation contract needed
by an isolated executor deployment. They do not themselves remove the agent's host
credentials or create a process/network sandbox.

**Lifecycle**

1. Authenticated application administration registers an immutable task for one tenant,
   agent subject and service credential using `POST /v1/tasks/register?tenant_id=...`.
   Supply a strict TaskAuthority, exact tool schemas and the approved adapter release's
   SHA-256 digest, plus `execution_domain` from the provisioned ledger's protected
   deployment configuration. Caller/model evidence cannot register its own task.
2. The agent submits a typed tool ActionRequest to `POST /v1/execution/grants` with its
   executor audience. The issuer checks both current tenant policy and the registered
   compiled grant. Evaluation alone returns a decision receipt, not an execution token.
3. ESCALATE creates an action-bound review. A distinct authorized reviewer may resolve
   it through the existing review endpoint. Approval cannot override BLOCK, a changed
   policy, changed arguments, a different principal/task or missing strict authority.
   An approved review can issue one grant; reusing it cannot mint fresh grants.
4. The credential-holding executor verifies the signature, principal, tenant/task,
   canonical action, adapter release, ledger domain, audience, key and expiry. It must validate current
   authority online through `POST /v1/execution/validate` using its separate EXECUTOR
   identity. No offline fallback is permitted for this path.
5. `MediatedExecutor` atomically reserves the nonce, effect and budget in a private SQLite
   ledger, rechecks authority before dispatch, then invokes its trusted adapter. Duplicate
   successful requests return the sanitized receipt without redispatch. Other keys cannot
   repeat the same effect unless the task explicitly permits repeatability.
6. Dispatch exceptions, crashes and uncertain provider responses leave an unknown/pending
   result. They retain reservations and cannot be blindly retried. Reconcile against an
   authoritative provider receipt before releasing or retrying the operation. There is
   no global exactly-once guarantee across arbitrary third-party APIs.

The relevant Python components are `ExecutionAuthority` in
`traceguard.control.execution` and `MediatedExecutor` in `traceguard.executor`. Configure
the executor with its own authenticated Actor, a trusted pinned issuer public key/key ID,
the deployed adapter artifact digest, a fresh online-validation callback and a narrow
dispatch function. Use the same private durable ledger for all replicas sharing the same
execution authority; the current SQLite implementation is a local deployment building
block, not a distributed database service. See `ledger_lifecycle.md` for mandatory
provisioning, expected-identity validation and offline migration. A missing ledger fails
closed; never replace it with a new database as automatic recovery.

The adapter digest must identify a verified deployed artifact; do not accept it from model
output or compute it from an untrusted request. The executor's handlers, OS identity,
credential storage and private ledger directory are part of the trusted computing base.
Separate them from the agent process and enforce network/filesystem isolation in the
deployment before claiming the stronger profile.

**Limits and failure semantics**

Grants expire within 60 seconds. Policy changes observed by pre-dispatch validation revoke
old grants; revocation cannot undo an already dispatched effect or eliminate every race
between remote authorization and a provider call. Application identity/revocation checks
remain necessary at ingress. The base `ControlPlane` stores state in memory; use
`SQLiteControlPlane` for the supported single-host durable issuer profile described in
`authority_storage.md`. External key management, distributed fencing and independently
validated operational recovery remain release gates.

Delegated observation fields are refused by this execution issuer until an authenticated
source adapter is supplied. This prevents unsigned source IDs from becoming authority.
Payment reservations are tested using disposable handlers and Decimal arithmetic; real
payment/currency/provider semantics remain experimental. Sanitized result receipts are
not a general data-loss-prevention or final-answer confidentiality guarantee.

Validation includes exact-action tampering, wrong identities/audiences/signatures/adapter
versions, expiry and policy revocation, action-bound review, executor restart/replay,
provider uncertainty, online-validation outage, concurrent budget reservations and API
role checks. All effect tests use disposable state and fake service handlers.
