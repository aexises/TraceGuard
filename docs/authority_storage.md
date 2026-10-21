# Persistent single-host authority

Use `SQLiteControlPlane` from `traceguard.control.storage` when issuer policies, tasks,
reviews and revocations must survive restart on one host. It is separate from the
execution ledger and is not selected by the bundled development API.

## Transaction and persistence contract

`SQLiteControlPlane` uses a private, single-host SQLite authority database. All
outer service/issuer operations take a SQLite write transaction, verify and reload the
signed snapshot, perform the operation, enforce quotas, and atomically save it. Nested
operations share the same transaction. Multiple processes on the same local database
serialize updates. This is intentionally a small bounded profile, not a distributed or
high-throughput database implementation; snapshot serialization is linear in retained state.

## Initialize and reopen

Initialize once through trusted administration with `initialize=True`. Subsequent starts
must use the default `initialize=False` with the same private signing seed and key ID.
Missing rows, missing databases, wrong keys, corrupt signatures and unknown schemas fail
closed. Keys are supplied externally, not stored in the database. Policies, task grants,
reviews, receipts, audit chains, epochs, issued grants and credential revocations survive
restart. Execution signing is purpose-separated and stable for the configured authority.

## Capacity and admission limits

The storage and HTTP layers have separate default bounds:

| Layer | Bound |
| --- | --- |
| Retained collections / per-tenant audit or policy history | 10,000 entries |
| Signed authority snapshot | 32 MiB |
| HTTP request body | 1 MiB |
| Action arguments | 64 KiB, 4,096 nodes, 16 levels |
| Concurrent HTTP requests | 16 |
| Authenticated credential requests | 120/minute |
| Active credential rate buckets | 1,024 |

HTTP limits apply through the configured API middleware, not to arbitrary direct Python
callers. Limits reject work rather than discard authority, audit history or uncertain
effects. Audit capacity exhaustion requires offline archival
and a reviewed migration; there is no automatic truncation. Expired decisions/reviews/
grants are pruned on transactions. Configure state volumes/backups with adequate quotas.

## Revoke credentials or suspend a tenant

`revoke_credential` and the admin API revoke a tenant credential and advance the policy
epoch. `suspend_tenant` stops agent/executor operations while allowing authorized recovery
administration. Suspension, resumption and revocation are durable and invalidate old online
grants. Offline read bundles retain their documented bounded stale-policy window.

## Back up, recover and rotate keys

1. Stop admission and fence every issuer/executor using the state. Preserve pending/unknown
   effect reservations; never restore a blank ledger to fix a timeout.
2. Use `backup(new_path)` for a consistent SQLite backup. Keep the externally supplied
   seed and a signed audit export in independently protected storage. Verify the restored
   snapshot and audit chain before reconnecting services.
3. For offline key rotation use `rekey(new_path, new_seed, new_key_id, authorized_admin)`.
   It preserves policies/tasks/audit and revocations, increments epochs and discards old
   issued grants/reviews/decision receipts. Verify the new database with the new seed.
4. Switch the fenced services to the new state, pin the new public keys/key IDs in
   verifiers, retire access to the old state and seed, and resume with newly issued grants.

## Operational limits

The operator's fencing, external key custody and independent checkpoints are necessary.
A valid old backup cannot be distinguished from a malicious rollback using only the
same host and signing secret. This implementation does not claim KMS integration,
distributed fencing, online key rollover or immutable external audit storage.
