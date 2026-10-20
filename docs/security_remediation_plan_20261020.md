# TraceGuard remediation plan — findings R01–R10

Plan date: 20 October 2026. Baseline: combined unmerged head
`aa34af2f2f673e1473629a136ae11f474236db0c`, incorporating PRs #21–#27.
This document records the implementation plan. The prior audit's
results describe that baseline and must remain unchanged as historical evidence.

Deliver nine scoped corrective PRs, followed by validation of the complete candidate.
Hold merge until the code-level acceptance gates below pass. Supported-release gates
for independent review, efficacy evidence, pilots and licensing remain separate.
The C01–C09 labels below are planning identifiers, not assigned GitHub PR numbers.
Owner labels identify engineering responsibilities to assign; no reviewer or pilot
organization is presumed to exist.

**Coverage and dependencies**

| Proposed PR | Finding | Owning role | Depends on | Required outcome |
| --- | --- | --- | --- | --- |
| C01 — Authorize task registration inside durable transactions | R01 / P1 | Authority engineer | Baseline | Revoked administrators cannot register through stale workers |
| C02 — Provision identified ledgers and persist task holds | R04 / P1, R05 / P2 | Execution/state engineer | Baseline | Restart, changed payloads and lost storage cannot reset enforcement history |
| C03 — Persist output disposition separately from execution | R02 / P1 | Runtime/release engineer | C02 | Replay preserves withholding without repeating a side effect |
| C04 — Enforce adapter-specific read resources in the kernel | R03 / P1 | Policy/adapter engineer | Baseline | Every strict integration enforces the same explicit object scope |
| C05 — Reserve and account for actual Inspect executions | R06 / P2 | Inspect integration engineer | C02, C04 | Approval, dispatch and native outcome history share one accounting domain |
| C06 — Align native shell exposure with reviewed effects | R07 / P2 | Tool/adapter engineer | C04, C05 | Authorized supported shell calls work; unsupported capabilities are withheld |
| C07 — Commit artifact content and publication metadata together | R08 / P2 | Artifact/recovery engineer | C03 | Publication has one authoritative, recoverable commit point |
| C08 — Authenticate peers before parsing and bound ingress time | R09 / P2 | Transport engineer | Baseline | Slow or unregistered peers cannot evade admission/deadline controls |
| C09 — Refresh affected dependency locks and scan the candidate | R10 / P2 | Dependency/release engineer | Baseline | Current affected profiles pass advisory and native compatibility checks |

C01, C02 and C04 start the critical security work. C03 follows C02. C08 and C09 can
be prepared independently, including an immediate advisory refresh. C05/C06 follow
the execution and resource contracts; C07 follows the output-disposition contract.
Freeze shared ledger/adapter contracts before downstream implementation to avoid
each integration inventing a different state machine.

Base the corrective stack on the verified combined head. Before implementation, check
remote PR heads and applicable instructions again. If the baseline changed, rerun the
affected reproductions and update the plan's base explicitly. Publish corrective PRs
as drafts when implementation is authorized; merge only after review and candidate
validation. Keep each PR title, tests and migration notes aligned with its final scope.

**Shared contracts to settle first**

1. **Authority:** reload current state, authorize against it, and mutate within one
   transaction. A successful check against a stale snapshot is not reusable permission.
2. **Execution domain:** approved task identity, budget, ledger identity and uncertainty
   state must remain stable across workers, restarts and supported integration routes.
   Agent-selected call IDs, executor audiences or changed generated text cannot create
   a fresh accounting domain. Keep the initial profile on one shared local ledger;
   distributed execution requires a separately validated shared-state/fencing design.
3. **Execution outcome:** distinguish `reserved/pending`, `not_dispatched`, `succeeded`
   and `unknown`. A timeout after dispatch never proves non-execution.
4. **Result disposition:** distinguish `pending_review`, `accepted_for_agent`, `withheld`
   and `review_required`, independently of execution outcome. Acceptance for agent
   context does not authorize final-answer, model-provider or artifact publication.
5. **Task hold:** allow at most one unresolved consequential reservation per task in
   the initial profile. A pending/unknown effect or required review withholds further
   consequential dispatch. Document any permitted recovery/receipt reads explicitly.
   Classify outbound requests by their actual effects rather than treating all reads
   as harmless. A timeout or restart cannot clear a hold automatically.
6. **Publication:** consumers observe only complete committed bundles. One authoritative
   publication record determines visibility and recovery; private mirrors cannot
   contradict an already published bundle.

These are proposed contracts. Implement and test them before describing them as guarantees.

**C01 — Atomic registration authorization: R01**

Primary files: `src/traceguard/control/execution.py`, `control/storage.py` and
`tests/test_authority_storage.py`. Review other authority entry points for the same
ordering error without expanding into unrelated refactoring.

- Enter `control.transaction()` before checking tenant membership, ADMIN role and
  credential revocation for registration. Keep the dependent existence check, task
  insertion and audit append in that transaction. Expensive pure schema compilation
  may precede it, but cannot replace authorization inside the transaction.
- Ensure all persisted security decisions use freshly loaded state. Preserve atomic
  rollback when validation, audit append, capacity enforcement or persistence fails.
- Add the two-instance revoked-admin reproducer as a denial regression. Coordinate
  concurrent revoke/register operations using barriers, with assertions based on their
  transaction order: a registration ordered after committed revocation must fail.
- Include wrong-tenant, missing-role, valid-administrator and rollback cases. A denied
  registration must leave no new task or successful registration audit event.

Acceptance: stale workers cannot create a task after revocation commits; an authorized
administrator can still register and execute an appropriately scoped task.

**C02 — Identified ledgers and durable task holds: R04 and R05**

Primary files: `src/traceguard/ledger.py`, `executor.py`, `runtime.py`, `security.py`,
authority/task-registration contracts and isolated fixture/configuration code.

- Separate trusted first-time provisioning from normal open. Normal connections must
  open an existing store without silently creating its file or tables.
- Add versioned ledger metadata and a persistent store/execution-domain identity.
  Require an expected identity from trusted deployment or approved registration
  configuration; an ID read only from the database cannot detect the wrong database.
  Bind mediated grants to the approved execution domain and ensure all executors for
  that task share its ledger. Check this binding before reservation or replay.
- Make missing, unexpectedly empty, incompatible or mismatched stores fail closed.
  A read-only embedded task may still omit a ledger if it has no consequential effects.
  Never offer automatic blank-store recovery as a timeout workaround.
- Add durable per-task holds in the same transaction as reservation/outcome updates.
  Pending work withholds additional consequential calls. An uncertain outcome retains
  the hold even if a later proposal changes content, object, amount, nonce or call ID.
- Clear a hold only through an authorized transition after definitive provider evidence
  or separately approved continuation. Require the old worker to be fenced before
  reconciling pending crash records. Keep a hold while any applicable reservation is
  unresolved; resolving one record cannot clear another unknown effect.
- Define trusted task identity once. Applications must not reset a task by changing a
  model-supplied ID, credential alias or executor audience.

Migration: provide an explicit, versioned, fenced migration with a verified backup and
recorded store identity. Preserve every prior reservation, amount, nonce and uncertain
record. Derive holds from existing pending/unknown rows. Invalidate/reissue incompatible
grants while preserving their execution history. A failed migration leaves the original
store usable under its old schema and keeps admission stopped; downgrade must not discard
new holds or reservation fields. Require a fresh approved domain if safe downgrade cannot
be supported.

Acceptance tests: restart with an intact ledger and changed payload still withholds;
two instances cannot reserve distinct consequential actions past an unresolved hold;
missing file, empty file, wrong mounted store and incompatible schema prevent dispatch;
the same valid grant cannot dispatch twice after failed reopen; legitimate known-complete
tasks continue within budget; reconciliation requires authorized, definitive evidence.

**C03 — Durable output disposition and safe replay: R02**

Primary files: `src/traceguard/ledger.py`, `runtime.py`, `executor.py` and result/release
contracts. Use the C02 schema/migration mechanism.

- Persist the execution outcome independently of the result disposition. A successful
  side effect starts with its result pending review when review is configured.
- Keep bounded result material private, bound to its action/receipt and relevant release
  policy version. Do not log raw secrets or hidden model reasoning. Redaction does not
  establish permission to return a result.
- Persist BLOCK_RESULT as withheld and post-run ESCALATE/provider uncertainty as the
  appropriate review-required state before returning. Enforce these states on restart,
  cached replay and every supported receipt-return path.
- Replay accepted observations only after applicable current authorization/release
  checks. Preserve a prior withholding decision until explicit authorized reconsideration;
  a restart or another stochastic model answer cannot silently overturn it.
- Recover an interrupted review without rerunning the effect. If its evidence/context
  cannot be reconstructed safely, retain withholding and require review. Missing result
  bytes are not a successful usable result.
- Treat legacy succeeded receipts as having unknown release disposition when no durable
  release decision exists. Migrate them to withheld/pending review, never automatically
  to accepted. Keep final-answer/provider/artifact sink permission separate.

Acceptance tests: BLOCK_RESULT and ESCALATE survive restart/replay; crash immediately
before/after each dispatch/result/review commit cannot release withheld bytes or dispatch
again; changed release policy is respected; an accepted result can be retrieved safely;
post-run provider outage preserves the effect receipt and task hold.

**C04 — Common adapter/resource authorization: R03**

Primary files: `src/traceguard/policy/kernel.py`, `effects.py`, versioned effect data,
`policy/engine.py`, `supervisor/agentdojo_pipeline.py` and dataset gateway adapters.

- Inventory every advertised read tool and its real schema/handler. Identify resource
  selectors and implicit resources, including filesystem paths, IDs, corpus roots and
  network destinations. Account for validated defaults that affect actual execution.
- Bind descriptors to adapter identity and schema version/digest. Map native fields
  such as `path` and `file` into reviewed resource semantics. Matching a familiar tool
  name alone must not establish the handler's effects.
- Put required resource checks in the compiled kernel. In strict mode, absent object
  authority withholds, including when the filename looks harmless. Support any broad
  read permission only through an explicit reviewed scope; add no implicit wildcard.
- Retain extra integration restrictions where needed, but require every advertised
  strict integration to enforce the kernel's invariant. Unknown mappings/schemas fail
  validation instead of inheriting guessed permissions.
- Version changed descriptors/contracts and document how existing grants are reapproved.
  Preserve clearly labeled research ablations without weakening the strict entry points.

Acceptance: the original unscoped read is withheld across the facade, kernel, dataset
gateway and applicable native integrations. Exact approved reads reach a real harmless
handler. Wrong paths/IDs, aliases, alternate native field names, unexpected defaults and
unsupported selectors fail consistently. Include ordinary filenames and not only names
matched by the sensitive-path detector. Document every intentional integration difference.

**C05 — Inspect execution accounting: R06**

Primary files: `benchmarks/datasets/inspect_integration.py`, `gateway.py` and native
Inspect integration tests. Depend on C02 and C04.

- Bind native task/call identity to trusted application task scope. Preserve identity
  across retries and rewrites; reserve the fully validated effective action before it
  can execute.
- Connect actual pre-dispatch and post-dispatch hooks to the shared accounting/hold
  contract. Reconstruct history from trusted execution records and correlate real
  native tool-call/result IDs. Tool-result text alone cannot prove that nothing happened.
- Record success, definitive non-dispatch and unknown outcomes explicitly. Budget and
  repeat checks include pending/unknown reservations and work across concurrent callbacks
  and supported restart paths.
- If the installed Inspect hook API cannot mediate a consequential operation completely,
  require a guarded executor/wrapper for that operation and withhold the unsupported
  direct path. Document the supported surface and its legitimate execution test; an
  unsupported feature must not be reported as securely executed.
- Maintain provenance observations separately from execution accounting. Adding an
  observation after success alone does not close concurrent approval or crash windows.

Acceptance: real Inspect callbacks/history approve and execute legitimate 60+40 work
under a budget of 100, while 60+61 cannot produce the second effect. Concurrent 60+61
proposals also stay within budget. Cover retry, duplicated native IDs, rewrites, missing
result, post-effect error, cancellation and restart. Use disposable fixture effects and
actual Inspect models/gateway; a fake gateway returning canned decisions is insufficient.

**C06 — Native shell/effect conformance: R07**

Primary files: native Inspect tool factory, effect descriptors/classification and tests.
Depend on C04/C05 so shell work uses the same authority and reservation contracts.

- Inspect the installed native `bash` schema and execution behavior. If retained,
  classify it as a command with a reviewed mapping and require explicit approved command
  arguments plus the supported sandbox profile. Do not grant arbitrary generated scripts
  by adding the name to a generic allowlist.
- Update the exposed tool inventory, effect catalog, schema/grant digests and migration
  notes together. Preserve the intended bounded timeout. Continue to withhold unknown
  tools and unsupported shell capabilities.
- Add a catalog conformance check covering every exposed tool through authorization
  and the final adapter. If safe support is unavailable, remove bash from the advertised
  strict tool set and record that limitation explicitly.

Acceptance: an explicitly authorized harmless native shell call completes in its
disposable sandbox; altered/ungranted command content is withheld; routing cannot invoke
a host shell; uncertainty, replay and timeout follow C02/C03. An absent implementation
cannot be represented by a test that merely constructs a tool or approves a fake call.

**C07 — Recoverable artifact publication: R08**

Primary files: `src/traceguard/release_gate.py`, report adapter/reconciliation,
sandbox artifact consumer contracts and `docs/data_release.md`.

Use one authoritative committed bundle in the consumer-visible namespace:

1. Prepare under a private directory that consumers cannot mount or enumerate. Validate
   every file, aggregate budget, hash, label and sink before publication.
2. Put the final file set and a versioned commit manifest in that bundle. Bind artifact
   identity, action digest, file hashes and release-policy decision. Flush files and
   required directories according to the supported local filesystem's durability model.
3. Publish the complete bundle with one serialized, non-overwriting same-filesystem
   directory rename; persist the parent-directory update before acknowledging durability.
   Bytes and the authoritative commit record become visible together.
4. Make the private quarantine manifest a recoverable mirror. A failure updating that
   mirror after publication cannot turn the authoritative published state back into
   quarantined/rejected. Return a truthful committed or publication-unknown outcome and
   recover it idempotently without rerunning the originating effect.
5. Reconstruct receipts/status from the committed bundle and verified hashes. Reject
   only unpublished artifacts; return an explicit already-published result otherwise.
   Withdrawal of a published artifact would be a separate authorized operation.

Migration: fence publishers and consumers, inspect legacy orphaned release directories,
and quarantine any bundle lacking sufficient verified publication evidence. Update both
producer and consumer visibility rules before claiming the invariant. Do not assume
directory rename alone creates a transaction across separate manifests/databases.

Acceptance: inject failures before/after each write, sync, rename and mirror update.
Restart recovery yields one consistent state and never exposes partial staging. Verify
retries, concurrent release/reject, missing/corrupt manifests, modified content and
provider reconciliation. After a committed rename, rejection cannot falsely report that
the visible artifact is unpublished. Test the documented supported filesystem/platform.

**C08 — Exact-peer admission and absolute ingress deadlines: R09**

Primary files: `src/traceguard/mtls.py`, isolated service configuration and transport tests.

- Resolve and authorize the exact verified certificate immediately after the TLS
  handshake, before HTTP request-line/header parsing. Retain CA validation, hostname/
  server-pin checks, role separation and registry revocation semantics.
- Define a monotonic absolute ingress deadline covering handshake, headers and body
  (initial default: five seconds total), with explicit byte/line/concurrency limits.
  Enforce it during I/O; checking elapsed time after a blocking read is insufficient.
- Bound unauthenticated handshakes and per-peer concurrent connections before admitting
  work. Reserve capacity so one authenticated peer cannot occupy every request slot.
- Release slots on every timeout, rejection, disconnect and exception. Separate ingress
  completion from effect execution: a client disconnect after dispatch cannot mark the
  effect not-dispatched or authorize a blind retry.
- Keep production front-proxy requirements explicit and test the selected configuration.
  Do not infer production transport hardening from using the standard-library server.

Acceptance: the original unregistered-peer probe is rejected before headers are read;
an authorized peer dripping headers/body still hits the absolute deadline within a
declared scheduling tolerance. Cover handshake stalls, over-budget headers, partial
bodies, slot cleanup, per-peer capacity, healthy-peer progress, registry revocation and
valid normal requests. Use disposable bounded loopback tests and a controlled transport
test host for concurrency; do not load-test production services.

**C09 — Current dependency remediation: R10**

Primary files: root/native Inspect lockfiles, relevant dependency metadata and release
scan evidence. This can start immediately while the P1 work proceeds.

- Recheck official advisory and package metadata at implementation time. The audit
  identifies 3.14.4 as the aiohttp fix floor; select a currently patched compatible
  version and update every affected lock. Do not describe that floor as the latest
  available release without verifying it.
- Preserve pinned upstream source revisions unless a justified source update is needed.
  Record any changed benchmark conditions and verify compatibility. Do not suppress
  advisories or remove a scan profile simply to make checks pass.
- Run the pinned scanner for core, all extras, native Inspect and native AgentDyn;
  retain advisory reports, dependency SBOMs, scanner versions and exact candidate/source
  digests. Report pinned VCS packages outside registry advisory coverage explicitly.
- Run fresh locked installs and real native API/tool compatibility checks. Refresh
  history/source secret scans. A scanner/network error remains an incomplete check.

Acceptance: the three reported aiohttp advisories are absent from both affected
environments, all required profiles complete successfully, and installed native tools
still pass their behavioral conformance tests. The final candidate must be rescanned
after all subsequent changes and immediately before merge.

**Candidate validation and closure**

Convert the audit probes into maintained secure-outcome tests in the owning PRs.
Preserve the original report/probe results as baseline evidence; do not leave assertions
expecting the vulnerable behavior as acceptance tests. Use a traceability matrix:
finding → contract → code revision → regression IDs → test evidence → review disposition.

The combined candidate gate requires:

- All ten findings mapped to implemented changes or an explicitly removed unsupported
  surface, with successful authorized behavior demonstrated for the supported product.
- Original attack/fault sequences now denied, durably withheld or recovered as specified,
  including restart, two-instance concurrency, changed-payload retry and crash boundaries.
- Full required unit/integration suite, Ruff, formatting and diff checks; supported
  Python 3.11/3.12 CI; fresh hash-locked installations and wheel/sdist/resource checks.
- Live Docker canaries and rebuilt three-container conformance on the final image,
  including replay/restart, data release, effect uncertainty and authority revocation.
  Required live cases must actually execute; a skipped canary cannot satisfy this gate.
- All four current dependency scans and redacted history/source scans completed, with
  their scope and VCS exclusions recorded. Candidate provenance must identify the exact
  commit, governed-source digest, tool versions, locks and image digest tested.
- Fenced migration/restore checks on disposable copies, covering pending/unknown effects,
  legacy result disposition, wrong/missing state, rollback failure and recovery receipts.
- Documentation updated to match constructor/API/schema changes, supported adapters,
  resource scope, result-sink permissions, recovery procedure and deployment limits.

Docker was unavailable during the audit. Provision a working disposable Docker test
host for implementation validation; do not replace that evidence with the old green CI
run or an in-process fake sandbox. No fixed future passing-test count is asserted here.

A finding is **implemented** after its code/migration work lands on the candidate and
its original repro is closed by the regression. It is **verified on the candidate**
only after relevant combined tests and review pass on that exact revision. Record failed,
skipped and unavailable checks. These statuses do not establish independent certification.

**Supported-release gates that this plan cannot manufacture**

After code closure, obtain independent security review, pre-registered held-out/adaptive
efficacy results, two actual application pilots, owner license approval and supported
operational recovery evidence. The owner currently has no external reviewers or pilots
arranged. Keep those gates open. Do not insert placeholder favorable reports or weaken
the release validator. Its hash checks establish document integrity, not the truth of
external work or superiority over another security framework.

Implementation status (20 October 2026): C01 implements R01 with six new durable
registration regressions; the focused authority/executor suite passes (25 tests).
C02 implements identified provisioning, domain-bound grants, durable task holds and
fenced legacy migration; lifecycle and regression evidence accompanies its corrective PR.
C03 implements separate durable result disposition, policy-bound replay and conservative
legacy receipt migration. Its restart/fault regressions preserve withholding without redispatch.
C04–C09 remain open. Candidate-wide validation and independent review remain pending.
No merges or releases are authorized by this plan.
