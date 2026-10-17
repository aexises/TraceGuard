# Security completion follow-up

This series follows the current-main reassessment at `4569d0a`. Each change must have
secure-outcome regressions; passing tests do not replace independent security review.

| Workstream | Implemented contract | Validation |
| --- | --- | --- |
| Staging and strict enforcement | Descriptor-relative no-follow regular-file copies; hardlink/special-file rejection; shared entry/byte/depth/time budgets; strict grants cannot be skipped by an LLM ablation switch | 118 focused staging, sandbox, strict-mode and supervisor tests passed |
| Embedded effects | Strict embedded side effects require an application-bound task and private SQLite ledger; shared reserve/unknown/receipt logic with isolated execution; provider-verified reviewer reconciliation | Restart, concurrent instances, task substitution and uncertain-effect regressions |

Sandbox `input_limits` apply while traversing and copying, before Docker starts. The
workspace and staging parent are application-owned. Concurrently changed objects are
rejected; a source name replaced after open cannot redirect the open descriptor.

Selecting strict scope runs explicit authorization even in an LLM-only research arm.
For a genuinely unguarded ablation select research scope explicitly. `mode="none"`
with strict scope is rejected. This changes strict ablation semantics intentionally.

Migration: `SecuredTools` now requires a trusted `task_id`; side-effect grants additionally
require `ledger_path`. Reuse that ledger across instances and restarts. A new ledger or
newly approved authority is a new authorization domain, never an agent-controlled reset.
Errors after dispatch are `EXECUTION_UNKNOWN`, retain reservations and stop the task.
Even repeatable tools cannot blindly repeat an uncertain effect. Embedded receipts redact
recognized credentials; comprehensive data-release controls are a separate boundary.

`MediatedExecutor.reconcile` requires a separate tenant reviewer and a configured trusted
provider lookup. The returned provider receipt must bind the reserved action digest.
Only definitive succeeded/not-dispatched outcomes can resolve uncertainty; never treat
an absent or timed-out provider response as proof of non-execution. Reconcile a pending
crash record only after fencing the old worker and confirming definitive provider state.

Still to deliver: an isolated authenticated
executor integration; durable issuer state and resource budgets; sandbox/quarantine/data
release controls; corrected effect metrics and reproducible evaluation; release security
evidence and support policy. External reviewers and application pilots are not arranged.
The repository owner's distribution license decision remains pending.
