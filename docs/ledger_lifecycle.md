# Execution ledger operations

Use the execution ledger to preserve effect reservations, task budgets and accepted
receipts across worker restarts. The supported profile uses one application-owned local
SQLite ledger for each execution domain. It is not a distributed replica or anti-rollback service. Protect the database,
WAL, configuration and backups together; privileged host administrators remain trusted.

## Provision once and pin the identity

Trusted deployment calls `ExecutionLedger.provision(path)` once and persists its returned
identity outside the database, in protected deployment configuration. Provisioning refuses
an existing path. Runtime constructors never provision or recreate storage. `SecuredTools`
requires `ledger_path` plus `ledger_id`; `MediatedExecutor` requires `execution_domain`.
Task registration must name that same domain, which is included in every signed grant.
All executor audiences for a task must use the same store. An independently initialized
store has a different identity and cannot accept that task's grant.

## Stop on missing or inconsistent state

Missing, empty, replaced, incompatible or wrong-identity storage stops admission. Do not
provision a replacement to handle an error. Fence admission/workers, recover the original
state and reconcile provider effects before resuming. Restoring an old backup without
reconciling later effects can repeat them; this library cannot prove an offline backup is
the latest state. Do not run old binaries against upgraded storage.

## Reconcile uncertain effects

Reservations serialize consequential actions per tenant/task. Pending or unknown records
hold all new consequential actions, including changed generated content, identities and
nonces. Successful known-complete actions retain their amounts for the task budget.
Reconciliation requires a separate reviewer and a trusted action-bound definitive provider
receipt. Resolving pending crash records also requires `pending_worker_fenced=True` only
after the old process is fenced; a caller-supplied status is never provider evidence.
Resolving one record does not clear another unresolved record. Embedded applications
must supply their own trusted reconciliation integration; automatic continuation is absent.

## Preserve result withholding

Schema v3 separates execution status from result disposition. A successful effect may
still have `pending_review`, `withheld` or `review_required` output. Those states withhold
agent-visible replay and hold new effects. Only `accepted_for_agent` with stored bytes
and the same result-policy binding permits replay. This is separate from provider,
artifact and final-answer sink permission. A prior withhold cannot be overturned by
another stochastic review during replay.

`SecuredTools(post_run_reevaluation=True)` durably reviews container results before
returning them. A review outage or interrupted commit retains withholding and never
reruns the effect. Set `result_policy_version` from trusted application configuration
and change it whenever the review prompt, provider/model, release interpretation or
other decision semantics change. Configured deterministic policy, task authority and
the review-enabled flag are also bound. A changed policy invalidates cached acceptance
durably, even if the old version is subsequently restored. There is no automatic
reconsideration of an already withheld or review-required record; trusted recovery must
reconstruct evidence and obtain new authorization while admission stays fenced.

## Migrate legacy state offline

For legacy v1/v2 ledgers, stop consumers and all dispatchers first. On a disposable copy,
call `ExecutionLedger.migrate_legacy(path, backup=unused_backup_path,
store_id=approved_identity, workers_fenced=True)`. It verifies an SQLite backup, validates
the legacy schema and transactionally upgrades metadata while retaining all execution and
reconciliation rows. V2 must retain its existing approved identity. All legacy successes
become `review_required`; historical receipt bytes do not establish release permission.
The backup is mode 0600 and must be retained securely. An error
leaves admission stopped; the schema transaction rolls back. A partially created empty
provisioning file is likewise an error requiring operator inspection, never automatic repair.

Approve that migrated identity in protected configuration and reapprove legacy authority
tasks through `ExecutionAuthority.bind_legacy_domain(..., workers_fenced=True)`. The task's
scope and history are preserved; pre-domain grants are invalidated and must be reissued.
Tasks lacking that binding cannot issue/validate executable grants. The fencing flags are
trusted operator attestations, not a distributed fencing implementation. No safe automatic
downgrade is supported: restoring old binaries/state requires a separately verified offline
recovery and continued accounting of every effect after the backup.
