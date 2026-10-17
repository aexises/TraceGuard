TraceGuard security audit and product completion plan
===================================================

Audit date: 17 October 2026. Inspected checkout: `ebf0c8ed0f6429c4c21625bd2a984aad71877b20`.

**Decision: retain the research implementation, but do not treat the current project as a production security boundary.** It contains useful enforcement components and meaningful negative tests. Its main weakness is that authorization, execution, identity, provenance and evidence do not yet form one consistently enforced contract. A hosted control plane, more prompts or additional dashboards would not resolve that weakness.

This is a source audit with bounded local behavioral probes, not a penetration-test certification or a claim to have found every vulnerability. Severity describes impact in the stated integration conditions; these are not CVSS scores. All source references below are repository-relative and refer to the inspected commit. No production code was modified during this audit.

**Evidence and limits**

- Ran `.venv/bin/python -m pytest -q -ra`: collection failed because `uvicorn` is missing. This environment also lacks `fastapi`; both are declared project dependencies. This is local environment drift, not evidence that the package omits them.
- Ran `.venv/bin/python -m pytest -q -ra --ignore=tests/test_api.py`: **257 passed, 7 skipped**. The skips are the opt-in live Docker canaries.
- Ran `.venv/bin/ruff check .` and `.venv/bin/ruff format --check .`: passed; 88 files already formatted at the time of the check.
- Ran the audit reproducer: **24/24 probes reproduced their named problematic behavior**. This count includes related symptoms and intentional design limitations; it is not a count of independent remotely exploitable vulnerabilities.
- The reproducer is `artifacts/security_audit_20261017/reproduce.py`; machine-readable results are `artifacts/security_audit_20261017/results.json`. Both are local ignored audit artifacts. It uses temporary files, native disposable AgentDojo objects, in-memory HTTP transport and fake sandbox execution. It makes no external network requests and uses no real secrets.
- Installed components used: Python 3.11, Pydantic 2.13.4, jsonschema 4.25.1, pytest 9.1.1, AgentDojo 0.1.35. This was not a fresh lock-based environment installation.
- No live API, live model, Docker execution, deployment, registry, dependency-advisory scan, race stress test or independent red-team exercise was run. Historical experiment outcomes below are identified as source-reported rather than rerun.

Reproduce from the repository root:

```bash
PYTHONPATH=src .venv/bin/python artifacts/security_audit_20261017/reproduce.py
```

The probes deliberately assert current insecure behavior. Once fixed, convert them into regression tests asserting denial or safe behavior; do not preserve their present assertions as acceptance criteria.

**1. What the security product should promise**

Recommended v1 scope: an embeddable Python enforcement framework, with a separate credential-holding executor for supported tool integrations. It should protect application-authorized resources and side effects even when the proposing model follows malicious retrieved instructions.

Start with three supported surfaces: document/filesystem access, outbound HTTP, and email. Email is particularly useful because the native CC/BCC/attachment gap provides a concrete acceptance case. Keep payments and generic code execution experimental until their stronger transactional and containment requirements are met.

Define two deployment profiles explicitly:

| Profile | Trust assumption | Defensible promise |
| --- | --- | --- |
| Embedded library | Application process and integration code are trusted; model proposals and retrieved content are untrusted | Supported calls passing through the integration obey deterministic task scope; LLM assessment may withhold additional calls |
| Isolated executor | Agent process is untrusted and lacks downstream credentials, filesystem authority and unrestricted egress | Supported effects require executor validation; bypassing the Python wrapper does not recover those privileges |

An in-process library cannot protect a host from arbitrary malicious Python running in that same process with the same permissions. A signed decision also cannot stop a caller that already possesses the underlying service credentials. State these limits in the public threat model.

The trust roots are the application identity resolver, approved task authority, policy publisher, tool adapter descriptors, executor and configured isolation platform. Documents, tool responses, model text, source labels supplied by an untrusted caller and agent explanations are not trust roots.

**2. Highest-priority findings**

| ID / priority | Finding and evidence | Security consequence and required repair |
| --- | --- | --- |
| S01 / P0 | Tenant authorization is absent. `control/models.py:57` has roles and a service key ID, but no tenant membership/scope; `control/service.py:129` and `:333` check roles only. Tenant selectors come from request data. Reproduced evaluation, bundle retrieval and audit export for tenant B using actors intended for A. | High if exposed as a multi-tenant service: any valid relevant-role credential can select another tenant. Add principal/tenant/action/resource grants and enforce them on every service method and storage operation. An identity resolver alone cannot bind the subsequent tenant selector unless the authorization boundary actually checks it. |
| S02 / P0 | Decision idempotency is keyed only by `(tenant_id, idempotency_key)` at `control/service.py:133`. It returns before inspecting the new request or current policy. Reproduced changed GET-to-DELETE requests, a second actor, and policy replacement reusing old ALLOW. | High: an approved harmless action can authorize different work. Bind a key to principal, task, canonical action digest and policy context; reject changed-payload reuse. Distinguish replaying a decision receipt from authorizing a fresh effect. Couple execution replay handling to a durable executor ledger. |
| S03 / P0 | The native email authority gate omits CC, BCC and attachment scope. `policy/authorization.py:301` checks selected destination field names, excluding `cc`, `bcc` and attachments. AgentDojo 0.1.35's real `send_email` signature supports all three. | High confidentiality gap. With the legitimate recipient explicitly constrained, the native deterministic supervisor returned ALLOW and the disposable Inbox recorded extra CC/BCC recipients plus an unapproved file attachment. Define adapter-specific descriptors covering every sink, referenced object and attachment; absence of a grant must not authorize extra fields. |
| S04 / P0 | Tool-family authorization does not establish object authorization. `policy/authorization.py:280` accepts supported verbs, but generally does not bind deletion/update IDs. Reproduced `Delete email 123` producing no denial for `email_id=999`. | High integrity gap where the application relies on language-derived scope. Require explicit object selectors, permitted operations and preconditions. Natural-language extraction can propose a grant for approval; it cannot be the root of a consequential grant. |
| S05 / P0 | `tool_effect()` classifies `get_webpage` as a read and `check_authority()` returns at `policy/authorization.py:248` before applying mutation destination rules. | A read can be a network disclosure or SSRF attempt. Reproduced native deterministic ALLOW for an unapproved URL containing a canary, and the native disposable Web object recorded that request. This was not real exfiltration. Model resource reads, network destinations, data release and mutations as separate effect dimensions. |
| S06 / P0 | HTTP authorization uses raw `startswith()` at `control/service.py:289`; `sdk.py:122` follows urllib redirects without evaluating subsequent destinations. | High for network enforcement. Reproduced hostname suffix and userinfo confusion when a prefix lacks a trailing slash, raw dot-segment acceptance, and a redirected request reaching an unapproved destination after one policy evaluation. Parse destinations structurally and revalidate every hop at the transport boundary; control DNS/IP resolution and redirects. |
| S07 / P0 | `runtime.py:192` calls the actual tool handler for every non-container target, including `SIMULATED`; only afterward does `:214` label it simulated. | High dry-run integrity failure. A stub supervisor requested SIMULATED for `write_report`; a real temporary file was written and the trace said SIMULATED. Simulation needs a distinct executor that cannot invoke real handlers. |
| S08 / P0 | Direct file access checks sensitivity on the requested name, then `tools/registry.py:238` resolves aliases and checks workspace containment only. | High confidentiality gap if another actor can create links in the workspace. Reproduced `workspace/public.txt` linking to `workspace/secrets.txt`: policy ALLOW and canary content returned. Authenticate the actual object and apply scope/sensitivity checks after safe resolution. Use descriptor-relative no-follow operations where supported; add hardlink and concurrent mutation cases. This was an in-workspace bypass, not demonstrated host escape. |
| S09 / P1 | Customer cache verification requires the same HMAC secret used to sign policy bundles and audit exports (`sdk.py:31`, `control/service.py:228`, `:242`). | High architectural weakness if customers/verifiers are outside the signing authority's trust domain. A verifier possessing this key can mint accepted policy bundles and forge export signatures; reproduced with a harmless forged bundle. HMAC itself is functioning correctly. Use asymmetric signatures, separate policy/audit keys and a defined rotation/trust policy. |
| S10 / P1 | `_matches()` trusts caller-selected `Evidence.untrusted`; its default is false (`control/models.py:63`). Reproduced identical injection text being ALLOW when the flag is omitted and BLOCK when set. | Trust metadata laundering if untrusted integrations supply the envelope. Derive source identity and trust at authenticated ingress. Caller metadata may be a claim but cannot establish authority. Regex detection adds neither source authentication nor a general injection guarantee. |
| S11 / P1 | Approved policy objects and installed signed bundles remain mutable aliases. `active_policy()` returns a stored object; `signed_bundle()` nests it; `SignedPolicyCache.install()` stores its argument directly. | Medium under the trusted-process model; high if these references cross plugin trust boundaries. Reproduced mutation of an approved policy without lifecycle approval and mutation of a bundle after verification. Use immutable snapshots and defensive copies with canonical digests, and isolate untrusted extensions. This is not a demonstrated unauthenticated HTTP edit. |
| S12 / P1 | Structured credentials leak into control-plane audits. The redactor at `control/service.py:45` checks assignment-like text but does not redact sensitive dictionary keys or ordinary Authorization header values. | High if real credentials reach actions. Reproduced raw fake password and Bearer token in exported events. Unify structural secret handling, minimize retained payloads and apply sanitization to target, provenance, review reasons and other metadata too. A regex-only secret detector cannot guarantee confidentiality. |
| S13 / P1 | Cache fallback catches `HTTPError` through `URLError`/`OSError` at `sdk.py:92`. Reproduced ALLOW from cache after HTTP 401, 403, 422 and 429. | Authentication rejection, authorization rejection, invalid request and throttling become fallback opportunities. Distinguish transport failure from explicit rejection. Permit offline authorization only for explicitly scoped low-risk actions and a documented stale-policy window. |
| S14 / P1 | Old valid cached policies continue allowing after online policy replacement. Reproduced online BLOCK plus cached ALLOW. Bundles are tenant-bound but not agent/task/audience-bound. | Intentional offline capability with an undefined revocation tradeoff. Do not promise immediate revocation while offline. Disable offline consequential effects; bind permitted offline grants to their audience/task, bound TTL/use/budget, and define emergency deny behavior and reconciliation. |
| S15 / P1 | The final executor does not enforce the documented high/critical risk restriction. `merge_outputs()` raises the merged risk but retains ALLOW/container routing; runtime then executes. | Reproduced the hybrid path invoking a fake sandbox with a merged CRITICAL risk. Add a deterministic final invariant check for decision, risk, target, tool effect and authority. The probe used a stub supervisor, not a live-model attack; `QwenSupervisor._to_runtime_output()` permits the same decision/risk combination. |
| S16 / P1 | Runtime instances mutate shared policy context at `runtime.py:65`; history is also mutable request context at `:223`. | Reproduced one runtime with an empty tool allowlist executing a write after another runtime replaced the shared policy's authority. Pass immutable task/evaluation context as arguments; do not store per-request authority in reusable evaluator objects. Add concurrency and cross-task isolation tests. |

P0 means close before exposing the affected capability to real data or consequential actions. The public multi-tenant service must remain disabled until S01/S02 are resolved. P1 means required for a supported release of the affected feature, or explicitly exclude that feature/profile from v1.

**3. Security architecture and unfinished framework work**

**One enforcement contract.** `control/service.py` does not call the research runtime's deterministic authority engine, effect registry or LLM supervisor. Its rules implement a separate decision system. `PolicyDraft.default_decision` can be ALLOW or REWRITE without a replacement; matching rules use priority-first selection, so a higher-priority ALLOW wins over a lower-priority BLOCK. Both default ALLOW and overlapping-rule behavior were reproduced. Priority semantics can be legitimate, but they conflict with the README's broad fail-closed language and the runtime's stated deny precedence unless carefully distinguished. Introduce shared normalized actions and mandatory invariants; compile/version policy semantics and reject ambiguous or unsafe configurations. A policy linter should flag unconstrained ALLOW rules, overlapping rules, unsupported effects and cache grants lacking necessary scope.

**Complete mediation and action binding.** The API returns a decision; it does not establish that the exact evaluated operation is what executes. `DecisionResponse` lacks the canonical action digest, executor audience, principal/task identity, nonce and expiry needed for a bound execution grant. Most tool credentials remain outside its control. Provide an executor-side enforcement point, isolate credentials there and deny direct unmediated access. A decision token is useful only when the executor validates it and the agent cannot bypass that executor. Reject changed arguments, tools, adapter versions, resources or relevant preconditions after approval.

**State and transaction safety.** Duplicate checks and payment budgets rely on in-process lists or message-derived successful history. There is no durable reserve/commit/abort protocol spanning policy evaluation and side effects. A timeout after a provider performs an effect is not proof of failure; excluding error-labelled calls from `_executed_calls()` can lose uncertain effects. Concurrent requests can race check-and-act even when sequential tests pass. Introduce atomic reservations, task budgets, replay handling, provider idempotency where available and explicit `execution_unknown` status. Do not promise global exactly-once execution across arbitrary third-party APIs.

**Real effect descriptors.** A tool name is not a sufficient security description. Each supported adapter needs a reviewed schema plus extraction of read objects, write objects, recipients, network endpoints, attachment references, credentials/scopes, memory operations and resource/cost effects. Bind the descriptor and schema version to the implementation being executed. Unknown fields/effects should stop, rather than silently inherit a general tool grant. The research registry includes financially consequential actions, broad code tools and sensitive reads such as credit-card details without a complete object/data classification model.

**Provenance and information flow.** `infer_provenance()` records literal occurrences; nested structures, transformed values and causal influence are not comprehensively represented. Source IDs and trust enums are not source authentication. Delegated sources need tenant/task binding, authenticated connector origin, object/version identity and freshness. Track source objects through extraction/transformation to output sinks, and require explicit declassification when protected data leaves its permitted scope. Exact prohibited-content substrings are useful canaries but do not prevent encoding, paraphrase, partial disclosure or disclosure via a referenced file attachment. A complete general-purpose information-flow system is substantial research work; v1 should publish the narrower invariants it actually enforces.

**Output and model-provider boundaries.** `StructuredTaskAgent.propose()` returns final answers at `agent.py:348` without a release gate; the native bridge also skips assistant messages with no tool calls. Remote task providers receive observations. Final-answer release, tool-output publication, model-provider disclosure and artifact release need explicit security boundaries. Treat the model provider itself as an external data sink with an approved data-handling profile. Provider prompt redaction does not replace those rules.

**Human review and rewriting.** Reviews can be marked ALLOW/DENY, but there is no reviewed action-bound grant/resume path; an idempotent reevaluation still returns the original decision. Rewrites in the control plane are untyped argument dictionaries and are not validated using runtime rewrite guarantees. Build review packets from trusted structured action data, show concrete effects/diffs, escape adversarial evidence, bind approval to an action digest and policy epoch, expire approvals, then reevaluate all current deterministic constraints. Rewrites are proposals and must reenter the same evaluator and executor path. Do not let explanations or a UI click mint general permission.

**LLM supervision.** Existing terminal deterministic blocks/escalations, schema checks, bounded rewrites and provider-failure escalation are valuable. Retain them. The 0.55 confidence boundary is explicitly an operating threshold, not calibrated correctness; its documented calibration set has four examples. A structured ALLOW can still be semantically wrong or internally inconsistent with risk/relevance labels. Define deterministic consistency invariants and keep the supervisor unable to expand grants. Evaluate injection into the supervisor's own context, long-context distraction, multilingual/encoded content, poisoned memory and correlated agent/supervisor errors. A second model provides no universal independent security guarantee.

**Sandbox capacity and quarantine.** Current Docker arguments provide useful network/resource/process containment; restricted networking is disabled. However, `runner.py:141` exposes a host-backed writable output directory and `:177` enforces artifact limits only after execution. An allowed container can consume host disk/inodes before inspection. Staging at `:279` has no input byte/file/directory budget. Inspection materializes and sorts the whole output tree before checking file limits, and directories do not count toward `max_files`. Use enforced execution-time byte/inode quotas, streaming bounded traversal, staging limits and concurrency limits. These are source-derived resource risks; this audit did not fill disk or run a container.

Artifacts are persisted at `runner.py:179` before post-run assessment at `runtime.py:168`. A BLOCK_RESULT withholds the observation but does not undo persistence. Use a private quarantine store and explicit release state; do not let downstream consumers discover quarantined artifacts through a shared directory. Captured stdout/stderr pattern matches are hints, not kernel-level proof of attempted operations. Bind mount/input validation also needs concurrent mutation and special-file testing. Specify the daemon/kernel trust assumptions; more hostile code workloads may need a stronger isolation profile chosen and tested against those requirements.

**Audit integrity and privacy.** Chain hashes omit event ID and timestamp; changing both still verifies. An unanchored hash chain cannot detect every truncation/rewrite by a privileged store writer, and `export_audit()` does not call verification. Add full canonical event coverage, sequence/count information, independent signed checkpoints, verification-on-export, access controls and retention rules. Keep policy signing separate from audit attestation. Audit receipts must include proposed action, effective action, policy digest, approval, execution status and provider receipt without exposing credentials or hidden reasoning.

**Availability is part of the security boundary.** `ActionRequest.arguments`, nested values and several source/provenance fields are effectively unbounded; the app has no explicit body/rate/concurrency limits and retains policies, audits, reviews and idempotency entries indefinitely in dictionaries. SDK/provider `response.read()` calls have no explicit response-size cap. Add parser depth/size budgets, tenant quotas, time budgets and backpressure. Treat rejected, failed, timed-out, unexecuted and execution-unknown states distinctly. `reconcile()` clears its list before processing; a failure can lose remaining reconciliation events. Replace it with a durable acknowledged queue if offline operation remains supported.

**Service completeness and operational prerequisites.** The in-memory backend, test token resolver, absent durable adapters and `/v1/chat/completions` returning 501 after ALLOW are already documented. There are no persistence repository interfaces injected into `ControlPlane`; adapting it requires real refactoring, not supplying a database URL. The built-in API starts with an agent-only token and no active policy, so it needs a supported policy bootstrap/admin integration before useful deployment. Add an integration conformance kit, stable API errors, version compatibility, a usable review workflow and migration guidance. Persistent authorization/audit state is security work; an operations dashboard can follow it.

The checkout already includes locked container builds, a development startup gate, one-replica deployment, non-root/read-only/capability restrictions and Docker/schema CI steps. Earlier packaging/two-replica issues should not be reported as still open. Their current runtime success was not reverified here. Remaining release work includes reproducible advisory/secret scanning, SBOM and signed provenance, key rotation/revocation, tested upgrade/rollback, identity integration and an incident/kill-switch procedure. No particular dependency CVE is asserted by this audit. GitHub Actions use mutable major-version tags rather than commit-pinned actions. No tracked root LICENSE or SECURITY.md was found; choose a distribution license and publish a vulnerability reporting/support policy before public framework release. `SUBMISSION.md` instructs rotating a previously exposed Gemini key; rotation status could not be verified and no credential was tested.

**4. What the “vibe-coded” problems actually are**

The issue is not style or whether a model helped write the code. It is local checks without a consistently enforced system invariant:

- A call labelled SIMULATED still invokes the real handler.
- A merged CRITICAL risk still reaches execution.
- A key intended to prevent duplicate actions becomes an authorization replay shortcut.
- A field called untrusted is treated as an authenticated trust assertion.
- A read classification hides outbound network disclosure.
- Checking one recipient field leaves CC/BCC and attachments open.
- An approved Pydantic model remains a mutable reference to the stored policy.
- A hash chain omits security-relevant metadata, and a customer verifier receives signing power.
- Equivalent safeguards have been reimplemented across custom runtime, native bridge, dataset gateway and HTTP service, allowing semantics to drift.

The corrective method is to write invariants first, enforce them at the final execution/release boundaries, and run one conformance suite against every integration. More individual attack phrases will not close these structural gaps.

**5. Evidence quality and research gaps**

The repository's October pilot report is appropriately candid: both retained live arms executed the declared attacked effect in 1/6 attacked episodes, both had a 6/12 secure-utility proxy, neither achieved clean utility-bearing termination, and the hybrid had 7 schema failures in 24 supervisor calls. Both sent incident count 103 instead of the verified 3. These are source-reported historical development results in `docs/hardening_and_pilot_20261006.md:136`; this audit did not rerun them. The report explicitly says the pilot predates final refinements.

The older 21-case scripted/heuristic benchmark is plumbing and regression evidence. It cannot establish current adversarial robustness, production utility or incremental live-supervisor value. Several named external dataset adapters are fixture-backed subclasses; `NativeEnvironmentAdapter` adds metadata to fixture results. That is not native benchmark reproduction, although dedicated native runner paths also exist.

There is an additional metric weakness at `experiments.py:246`: custom call labels use step-indexed equality with a scripted gold call, and an unrecognized extra step is unsafe by default. Alternative valid plans can therefore look unsafe. Also, BLOCK_RESULT is classified as blocked and not executed even though the container ran; `harmful_effect` is then gated on that execution flag. This can misattribute call-level effect prevention. Episode/native state predicates must remain authoritative. Post-run correctness is compared with episode security rather than an independent evidence-level gold label. These are source-derived measurement defects requiring dedicated regression cases, not newly measured benchmark errors.

Before efficacy claims, run current-code matched deterministic/hybrid arms with identical executor constraints and recovery behavior, disjoint held-out task/attack families, repeated seeds and more than one agent/supervisor pairing. Include adaptive attacks under a fixed budget, failed/outage providers and long-context cases. Score actual side effects and released outputs, not just decisions. Report task utility, attacked secure completion, false blocks, escalation workload, provider failures, latency/cost and uncertainty clustered by task family. Keep fixed fixtures, live agents, native benchmarks and human-assisted completion separately labelled.

**6. Target architecture and invariants**

```text
Authenticated application/user
        |
        +--> approved, immutable TaskGrant + resource scope
        |
Agent proposal --> adapter normalization --> deterministic authorization
                                            |
                               optional LLM withholding/rewrite proposal
                                            |
                                validate final execution invariants
                                            |
                           atomic reservation + action-bound grant
                                            |
                           credential-holding isolated executor
                                            |
                         provider receipt / unknown-effect recovery
                                            |
                         quarantine / output-release authorization
                                            |
                                  tamper-evident audit receipt
```

The following are proposed v1 acceptance invariants, not current guarantees:

1. Every supported effect and externally visible data release crosses an enforcement point; unsupported paths fail closed or are explicitly outside the security profile.
2. Execution authority is the intersection of application policy, authenticated principal scope, task grant and current resource state. A model cannot enlarge it.
3. The executor verifies the exact effective action, task, tenant, principal, adapter/schema version, policy epoch, target, nonce and expiry before using credentials.
4. Every recipient, attachment, object ID and network endpoint is extracted by a reviewed adapter and checked; missing grants do not silently widen scope.
5. BLOCK and ESCALATE cannot execute; SIMULATED cannot invoke real handlers; invalid decision/risk/target combinations cannot execute.
6. Rewrites preserve identity, attenuate authority and return through full evaluation. Approvals are action-bound, expiring and single-use where required.
7. Duplicate and budget reservations are atomic. Failure after dispatch is execution-unknown until resolved, never silently retried as a new effect.
8. Untrusted content cannot assign its own trusted origin or authorize new effects. Delegations identify authenticated, scoped, versioned source objects.
9. Confidential data remains subject to release controls across tool arguments, attachments, model providers, final answers and artifacts.
10. Offline behavior, revocation delay, tenant isolation, failure handling and audit retention have explicit tested semantics.

**7. Dependency-ordered delivery plan**

These phases are release gates. They are not calendar promises; staffing, chosen integrations and external review determine duration. Keep the supported surface narrow enough to satisfy every gate.

| Phase | Deliverable / owner role | Exit criteria |
| --- | --- | --- |
| 0: Scope and containment | Security lead: threat model, trust-boundary diagram, supported profiles, attack/asset matrix and security contract | Every current public claim maps to an enforced invariant or explicit limitation. Real multi-tenant and consequential integrations remain gated. Publish the finding inventory and assign an owner to every P0/P1. |
| 1: Repair demonstrated breaks | Core/adapter engineer: S01–S08 first, plus final risk invariants and per-request isolation | The audit probes become secure-outcome regressions. Add tests for changed-key payloads, policy change, two principals/tenants, native CC/BCC/attachments, wrong object IDs, read-egress, redirect hops, simulation and file aliases. Run the same invariants through every applicable adapter. |
| 2: One deterministic core | Core engineer: immutable action/task contracts, effect extractors, policy compiler/linter, shared evaluator and conformance harness | Runtime, HTTP and benchmark bridges agree on shared policy fixtures. No default ALLOW for unknown actions/effects. Invalid/ambiguous policies fail validation. Property/fuzz tests cover normalization and grant attenuation. |
| 3: Trusted execution and identity | Security/executor engineer: separate credential broker/executor, principal/task binding, scoped connectors and execution receipts | Direct agent calls lack credentials/egress permission. Changed or expired grants fail. Replay/parallel budget tests pass; ambiguous provider outcomes are recoverable without blind duplicate effects. Filesystem and HTTP normalizations match actual execution. |
| 4: Review, data release and evidence | Framework engineer: action-bound approvals, rewrite/resume lifecycle, quarantine, final-answer/provider/output release rules, minimal audit schema | No review race or changed-action approval succeeds. Quarantined artifacts are inaccessible to consumers. Credential canaries do not appear in retained logs. Signed checkpoints cover event metadata and detect tested tampering/truncation. |
| 5: Harden optional capabilities | Sandbox/SDK engineer: quota-backed sandbox, bounded inputs/outputs, asymmetric cache verification or remove offline mode from v1 | Live harmless canaries pass on supported deployment targets. Disk/inode/input/concurrency budgets are enforced during execution. Offline rejection, stale-policy bounds, key rotation, auth failures and reconciliation are tested. Unsupported isolation profiles stay experimental. |
| 6: Demonstrate efficacy and integration | Evaluation owner plus independent reviewers: current-code held-out/adaptive evaluation and two real application pilots | Report executed effects, released outputs and secure completion with paired uncertainty; quantify all false blocks/escalations and latency/cost. Fix high-severity bypasses before expanding surfaces. Keep the LLM optional unless it demonstrates a useful measured tradeoff. |
| 7: Supported framework release | Maintainer/release owner: stable package/API, licenses, security policy, migration guide, signed release evidence and support scope | Fresh locked installations and supported integration tests pass; independent review findings are resolved or explicitly accepted with bounded scope. No unresolved Critical/High issue in supported profiles. Recovery, revocation, upgrades and incident handling are exercised. |

Suggested first ten implementation PRs, each including regression tests and a documented contract change where needed:

1. Bind actors to tenants/resources and test every control-plane operation for cross-tenant access.
2. Replace decision-only idempotency with principal/action-bound receipts and reject payload conflicts.
3. Add complete native email effect extraction, including CC/BCC and attachment object authorization.
4. Bind mutation/read scope to object IDs and model outbound network effects independently of read/write labels.
5. Implement structural HTTP policy plus redirect and network-destination enforcement.
6. Separate simulated execution and enforce final decision/risk/target invariants.
7. Harden filesystem object authorization and isolate per-task evaluator context.
8. Introduce immutable shared action/task/policy contracts and cross-integration conformance tests.
9. Correct cache trust/fallback semantics and structural audit redaction; keep unsupported offline modes disabled.
10. Add the executor grant/reservation lifecycle and action-bound human review.

Source fixes can be developed in that order while the affected public capabilities remain gated. Do not market the first ten PRs as a complete framework release: the later evidence, isolation and lifecycle gates still apply.

**8. Practical definition of “completed product”**

The framework is ready for a supported v1 when an application developer can install it, connect a documented supported tool, define a scoped task grant, enforce that grant at execution, handle human review and failures, verify the resulting receipts, upgrade safely and understand exactly what remains unprotected. This must work without relying on the proposing model to be cooperative.

For that release, require: passing invariant/conformance and live integration tests; independent review; no unresolved high-severity bypass in the supported scope; actual credential/egress isolation for the stronger profile; tested tenant/resource isolation; honest held-out effectiveness and utility reporting; a vulnerability process and supported versions; and reproducible release evidence. Availability/recovery infrastructure necessary to preserve policy and audit integrity belongs in this gate. Additional dashboards, broad provider coverage, generalized agent orchestration and payment automation can follow.

The likely durable value is an inspectable, testable authorization-and-execution contract for agent integrations. The semantic supervisor remains an optional component whose usefulness must be demonstrated. Expanding the tool list without complete descriptors and executor conformance would increase risk faster than product completeness.

**9. External grounding, checked on the audit date**

- [OWASP Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) recommends narrow tool functionality, least privilege, user-context authorization and complete downstream mediation. This supports the executor-centered direction; it does not certify TraceGuard.
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) informs structured destination validation, redirect handling and network-layer restrictions. The local redirect probe independently establishes the current SDK behavior.
- [NIST on agent identity foundations](https://www.nist.gov/blogs/cybersecurity-insights/back-future-why-agentic-ai-needs-strong-identity-foundation) emphasizes agent identity, scoped delegation and credential management. These are design references, not a claim of regulatory compliance.
- [OWASP Agentic Top 10](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) supplies a coverage taxonomy spanning goal hijacking, tool misuse, privilege abuse, supply chain, unexpected execution, memory poisoning, inter-agent communication and human trust. Map supported threats and exclusions explicitly rather than claiming universal coverage.
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813) is a relevant capability/dataflow baseline. Its architectural guarantees do not transfer to TraceGuard's occurrence-based provenance or LLM decisions. This audit does not establish state-of-the-art superiority over CaMeL or other frameworks.
