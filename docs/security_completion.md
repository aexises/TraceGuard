# Security completion follow-up

This series follows the current-main reassessment at `4569d0a`. Each change must have
secure-outcome regressions; passing tests do not replace independent security review.

| Workstream | Implemented contract | Validation |
| --- | --- | --- |
| Staging and strict enforcement | Descriptor-relative no-follow regular-file copies; hardlink/special-file rejection; shared entry/byte/depth/time budgets; strict grants cannot be skipped by an LLM ablation switch | 118 focused staging, sandbox, strict-mode and supervisor tests passed |
| Embedded effects | Strict embedded side effects require an application-bound task and private SQLite ledger; shared reserve/unknown/receipt logic with isolated execution; provider-verified reviewer reconciliation | Restart, concurrent instances, task substitution and uncertain-effect regressions |
| Persistent authority | Signed bounded transactional SQLite state, stable separated execution keys, restart/recovery, backup/offline rekey, durable revocation and tenant suspension, JSON/concurrency/rate budgets | Restarted grants/reviews, rollback-on-quota, concurrent instances, corrupt/missing state, backup/rekey and ingress regressions |
| Sandbox and release | Kernel tmpfs byte/inode quotas; bounded isolated export; private hashed quarantine and explicit atomic release; model-provider/final-answer sink gates | Quarantine, tamper/rejection, secret canary, provider withholding and Docker quota canaries |
| Isolated integration | Separate non-root agent/issuer/executor containers, exact mTLS workload identities and server pins, verified deployed adapter, private persistent state and constrained report publication | Live loopback mTLS and three-container direct-bypass/replay/restart/egress canaries |
| Evaluation accounting | Dispatch/release/uncertainty separated; novel plans unlabeled; action-bound independent call/effect labels; case/family-clustered paired uncertainty; frozen complete trace-bound comparison protocol | Result-blocking, unknown effects, alternative plans, changed evidence, clustered seeds and incomplete/unmatched protocol regressions |

Sandbox `input_limits` apply while traversing and copying, before Docker starts. The
workspace and staging parent are application-owned. Concurrently changed objects are
rejected; a source name replaced after open cannot redirect the open descriptor.

Selecting strict scope runs explicit authorization even in an LLM-only research arm.
For a genuinely unguarded ablation select research scope explicitly. `mode="none"`
with strict scope is rejected. This changes strict ablation semantics intentionally.

Migration: `SecuredTools` now requires a trusted `task_id`; side-effect grants additionally
require `ledger_path` and the expected `ledger_id` from trusted deployment configuration.
Provision once, then reopen only that identified store across instances and restarts.
See `ledger_lifecycle.md` for fenced migration and recovery; changing authority or credentials
does not clear an unresolved task hold or budget in that domain.
Errors after dispatch are `EXECUTION_UNKNOWN`, retain reservations and stop the task.
Even repeatable tools cannot blindly repeat an uncertain effect. Embedded receipts redact
recognized credentials; comprehensive data-release controls are a separate boundary.

`MediatedExecutor.reconcile` requires a separate tenant reviewer and a configured trusted
provider lookup. The returned provider receipt must bind the reserved action digest.
Only definitive succeeded/not-dispatched outcomes can resolve uncertainty; never treat
an absent or timed-out provider response as proof of non-execution. Reconcile a pending
crash record only after fencing the old worker and confirming definitive provider state.

See `authority_storage.md` for the single-host profile, capacity and offline rotation
workflow. External KMS/fencing/checkpoint integration is not supplied by a local snapshot.

See `data_release.md` for the narrowly supported text/JSON classification profile. This
requires trusted application/source labels and is not general-purpose semantic DLP.

The isolated integration supports the narrow report store, not arbitrary external providers.
See `isolated_executor.md` for conformance and target-platform trust assumptions.

See `security_evaluation.md` for the implemented evaluation contract and the external
held-out/adaptive measurements still required. No new live-model efficacy result is claimed.

Release assurance now includes a private reporting route, support policy, pinned
history/source secret scanning, core/all-extra advisory scanning and dependency
SBOMs, immutable Action references, and a source-bound evidence gate before candidate
artifact attestations. See `release_assurance.md` for commands and the review/pilot packet.
External reviewers, application pilots, independent held-out results and the owner's
distribution license decision remain pending. These are release blockers, not completed
validation. The manual candidate signing workflow has not been executed.

The original follow-up series covers #21 staging/strict mode, #22 durable effects,
#23 persistent authority, #24 sandbox/data release, #25 isolated execution,
#26 effect-grounded evaluation, and #27 release assurance. The prerequisites are now
included in `main`. For ordered integration, #27 was retargeted to `main` after the
remaining PRs were detached from a native stack rooted at the old executor branch.
The subsequent corrective series #28–#36 preserves its individual changes, with the
dependency correction propagated through its prerequisites before merging. GitHub's
PR history records the merge status of each change. Merge status does not
establish deployment, live-model efficacy or independent security review.

Historical validation of the original stack on October 17: 464 tests passed with Docker
canaries enabled and optional Inspect installed; Ruff and formatting passed; source
and wheel distributions built; a fresh hash-locked Python 3.12 runtime installed the
wheel and passed smoke/resource checks outside the checkout. The final locked image
passed the three-container report canary before/after issuer restart. Core (21),
all-extra (147), native Inspect (97) and native AgentDyn (147) resolved registry
dependency records had no known advisory findings at scan time. Redacted history
and publication-source scans had no findings. The two pinned upstream VCS benchmark
packages are outside registry advisory coverage and are recorded in the scan report.
Fresh native AgentDyn installation, suite loading and provider imports passed without
a model. The release-evidence command exited with a missing-evidence error as intended.
These checks do not establish live-model efficacy or independent assurance.
They are not current advisory evidence; use fresh scans of the corrective candidate
with the patched dependency locks introduced in #36 and backported for integration.
