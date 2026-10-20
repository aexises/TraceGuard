# Corrective security implementation — 20 October 2026

Nine corrective PRs implement the ten findings against the combined unmerged baseline
`aa34af2f2f673e1473629a136ae11f474236db0c`. They were initially delivered as drafts;
GitHub's PR history records their subsequent ordered integration. No release is claimed.
The original audit describes the old baseline; these results do not retroactively change it.
Implementation and maintained regressions are complete for the narrowed supported surface.
Independent review and supported-release approval remain outstanding.

| Finding | Corrective PR | Implemented behavior | Maintained regression evidence |
| --- | --- | --- | --- |
| R01: stale administrator revocation | [#28](https://github.com/aexises/TraceGuard/pull/28) | Reload, authorize, insert task and append audit in one durable transaction | `tests/test_authority_storage.py`: stale/competing revocation, tenant/role denial, rollback, valid registration |
| R04: lost task hold on restart | [#29](https://github.com/aexises/TraceGuard/pull/29) | Pending/unknown effects hold the tenant/task, independent of changed payload, credential or audience | `tests/test_embedded_effects.py`, `tests/test_ledger_lifecycle.py`: changed generated text, restart, distinct concurrent effects, multiple legacy unknowns |
| R05: silent ledger recreation | [#29](https://github.com/aexises/TraceGuard/pull/29) | Explicit provisioning; existing-store open and per-connection identity/schema validation; signed domain binding | `tests/test_ledger_lifecycle.py`: missing/empty/wrong/replaced/schema state, lost-store valid-grant replay, fenced backup/migration rollback |
| R02: withheld result replay | [#30](https://github.com/aexises/TraceGuard/pull/30) | Execution status and result disposition persist separately; only accepted bytes under the same policy can replay | `tests/test_result_disposition.py`: block/escalation/outage/review interruption/policy change/missing bytes/legacy receipts; live Docker restart cases in `tests/sandbox/test_docker_canaries.py` |
| R03: missing common read scope | [#31](https://github.com/aexises/TraceGuard/pull/31) | Reviewed schema-bound adapter mappings; exact object authority, defaults and implicit corpus resources checked in the kernel | `tests/policy/test_read_resources.py`: original ordinary-file repro across kernel/gateway/facade, real approved file/corpus handlers, native selectors/defaults, unknown mappings |
| R06: Inspect approval accounting | [#32](https://github.com/aexises/TraceGuard/pull/32) | Strict consequential approval-only route rejected; explicit guarded native dispatch reserves and accounts for actual outcomes | `tests/test_inspect_execution.py`: actual native ToolDefs/ToolCalls/Approval/messages, 60+40 utility, 60+61 denial, concurrency, IDs, rewrite resubmission, cancellation/error/missing result, restart |
| R07: unsupported native shell exposure | [#33](https://github.com/aexises/TraceGuard/pull/33) | Unsupported bash/Python/editor/memory removed from the advertised strict standard-tool factory; broader surface requires research opt-in | `tests/test_inspect_compatibility.py`: strict inventory-to-kernel resource conformance, research-only capabilities and unsupported memory refusal |
| R08: artifact commit inconsistency | [#34](https://github.com/aexises/TraceGuard/pull/34) | Private preparation, self-contained public commit, serialized rename and parent sync; private mirror cannot reverse public truth | `tests/test_artifact_recovery.py`: write/sync/rename/mirror failures, corrupt/missing/extra bytes, reject/release race, legacy quarantine and provider receipt recovery |
| R09: slow/unregistered TLS ingress | [#35](https://github.com/aexises/TraceGuard/pull/35) | Exact peer admission before HTTP parsing, absolute I/O watchdog, header/body limits, handshake/peer capacity and fresh registry check | `tests/test_mtls_ingress.py`: pre-header denial, header/body drip, handshake stalls, healthy-peer progress, budgets, revocation and completed-ingress semantics |
| R10: current dependency advisories | [#36](https://github.com/aexises/TraceGuard/pull/36) | Both affected locks upgraded to aiohttp 3.14.5/yarl 1.25.1; solver floor added, upstream VCS revisions preserved | Four complete registry advisory/SBOM profiles; fresh locked installations and actual native compatibility checks; redacted source/history scans |

The deterministic boundary has positive and negative execution evidence: approved file
and corpus handlers execute; native fixture effects can spend 60+40 but not 60+61;
approved isolated reports publish once; accepted container results replay and blocked
results remain withheld across restart. These tests establish specific checked behavior,
not completeness against arbitrary attacks or superiority over another framework.

## Pre-integration candidate validation

Executable candidate commit: `6b58a35be3d9c9210b76649a54f144a118afc00c`.
Documentation-only delivery commits may follow; compare the governed source digest rather
than treating an older green run or a similar branch name as evidence for changed code.
Final scan metadata records the actual scanned Git revision and governed-source digest.

- Fresh root all-extras environments installed from the hash lock on Python 3.11.15 and
  Python 3.12.2, including the built non-editable TraceGuard package.
- Python 3.11: **540 passed, no skips**, with `TRACEGUARD_RUN_DOCKER_TESTS=1`.
  All eleven real Docker cases executed, including the two new strict runtime restart
  cases for accepted and withheld post-run results.
- Python 3.12: **529 passed, 11 Docker cases skipped**; those cases executed on 3.11.
  Live loopback TLS integrations executed on both versions. Linux CI remains separately
  checked at the PR head; local macOS execution is not Linux reproduction.
- Rebuilt three-container conformance passed: one authorized report, no replay effect,
  persistent issuer restart, changed-grant/scope denial, role separation, no agent access
  to private state, denied direct writes, internal networking and blocked external TCP.
- All four advisory profiles completed: core **21**, all-extras **147**, native Inspect
  **97**, native AgentDyn **147** registry packages, with **zero reported advisories**.
  Gitleaks history and publication-source scans reported **zero findings**. Each profile
  has a dependency report and CycloneDX SBOM. Scanner/network failure is never a pass.
- Fresh native Inspect installed its separate pinned VCS environment plus TraceGuard's
  hash-locked core and built wheel. Actual native file/list/grep schema and approval
  allow/deny cases passed: Inspect 0.3.281, Inspect Evals
  `0.16.1.dev3+g99ef14c96`, aiohttp 3.14.5. Root native effect tests exercised real decorated
  tools and framework messages through guarded dispatch; no real payments occurred.
- Fresh native AgentDyn installed its unchanged locked revision; provider imports and
  `get_suite('v1.2', 'workspace')` passed. The upstream SDK emitted a future-removal warning
  for google-cloud-storage <3; that warning was not suppressed or counted as a failure.
- Wheel and source distribution built successfully. Installed CLI smoke and packaged
  ablations, sandbox profiles, prompts and both effect catalogs passed outside checkout.
  Ruff, formatting and diff checks passed.
- Disposable migration tests preserve nonces, amounts, receipts and uncertainty, require
  fencing, verify backup integrity, reject wrong schemas/identities and roll back failed
  upgrades. Legacy domain reapproval also verifies that unrelated valid task grants survive migration.
  These are local recovery tests, not an independently witnessed operational drill.

The Linux TLS client may receive an early 403 or an early closed stream for an
unregistered certificate. The existing end-to-end assertion now permits both denial
outcomes; the separate test requires pre-header rejection and verifies no dispatch.

Local evidence (ignored artifacts/logs; CI publishes its own corresponding artifacts):

```text
artifacts/security-candidate-20261020/scan.json
artifacts/security-candidate-20261020/*-advisories.json
artifacts/security-candidate-20261020/*-sbom.json
artifacts/security-candidate-20261020/{history,source}-secrets.json
artifacts/isolation-conformance-candidate-20261020.json
/private/tmp/traceguard-candidate-py311-final-tests.log
/private/tmp/traceguard-candidate-py312-final-tests.log
/private/tmp/traceguard-candidate-build.log
/private/tmp/traceguard-candidate-package.log
artifacts/package-candidate-20261020.json
```

## Pre-integration reproducibility identifiers

| Item | SHA-256 / pinned version |
| --- | --- |
| Governed source digest | `c4e13399910bc64151e3cba57bf034aecd4ad07ecc2d8078cb72f287bbe988c2` |
| Deployed adapter digest | `80966806d3fcad3b837ad04b127cc96a6a014a6850cf8eef267ff72b8e8fe200` |
| Local ARM64 image ID | `sha256:2803433b64d251dc896d872403955d8219a318eacc0f8106d8734aa1b8f0e122` |
| Pinned Python base image | `sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4` |
| Root lock | `02960177bb0aff40d515769f807277be679b76b50b277fd1d49e6ca236ce2f8c` |
| Native Inspect lock | `0aee8dec127c16b01219504a8d1e57753e717211c3d2d866436554880f455e4a` |
| Native AgentDyn lock | `0d0312cd185b1766b2ac4b76a95768c109c356f45743c7476b00c3ba5383babb` |
| Tool versions | uv 0.13.1, Gitleaks 8.30.1 (verified archive), pip-audit 2.10.1 |

The image's copied source and adapter match the candidate. The final additions to tests
and CI are outside the Docker build-context allowlist. Local image IDs and adapter hashes
do not replace registry provenance/signatures for a release. Pinned VCS `inspect-evals`
revision `99ef14c96efb4a4d36c344b313ca734074af88bf` and AgentDyn `agentdojo` revision
`5353cf7615b135cace8d07c8f12dac53a16b6db3` are recorded outside registry advisory coverage;
zero registry findings is not a source audit of those upstream repositories.
The package evidence JSON records the final wheel/source-distribution hashes and build
revision separately, avoiding a source archive containing a report with its own hash.

The three original advisories list 3.14.4 as the patch floor. Official PyPI metadata
reported 3.14.5 at implementation; it was selected and tested without changing the
upstream framework pins. Sources: [initial-header timeout](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5wr8-gcqf-gqf3),
[resource exhaustion](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-2g87-pp6c-29x5),
[shared Secure cookie](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-494j-54xm-rwp3),
[official package metadata](https://pypi.org/pypi/aiohttp/json).

## Migration and release disposition

Use `ledger_lifecycle.md`, `read_resource_contract.md`, `inspect_execution.md`,
`data_release.md` and `isolated_executor.md` before upgrading. Constructor/grant/storage
contracts changed deliberately. Fence old workers and consumers, retain verified backups,
preserve the approved execution domain, reapprove changed adapter schemas, reissue old
grants, and reconcile provider effects. Never recreate a missing ledger to resume work.
An accepted agent observation is separate from permission to release artifacts, model
input or final answers. Unsupported strict adapters remain withheld.

During ordered integration, the remaining PRs were detached from a native stack whose
trunk was the already-merged executor branch. Each PR targets `main` when its predecessors
have landed. The four dependency manifest/lock corrections from #36 were backported to
#27 and merged forward through #28–#35, preserving existing commits and each corrective
implementation. Earlier failed advisory checks remain historical failures; fresh CI must
validate the updated heads. Application runtime code is unchanged by this integration.
Linux CI exposed an additional race in the conformance fixture: the executor could be
contacted before it began listening. A bounded listener probe now precedes each initial
service launch and issuer restart. It sends no application request and never retries
consequential dispatch. Delayed-start and unavailable-listener regressions verify this
behavior. The correction was applied to #33 and propagated through #34–#36.

The integrated candidate passed **542 tests with no skips** on Python 3.11, including
the eleven Docker cases and two new readiness cases; Ruff, formatting and diff checks
passed. The corrected three-container probe passed against a source-matching #34 image.
Local logs are `/private/tmp/traceguard-ordered-integration-final-tests.log` and
`/private/tmp/traceguard-pr34-readiness-canary.log`. These integration checks supplement
the historical validation above. Their updated governed source digest and fresh scan
revision are recorded separately in
`artifacts/security-ordered-integration-final-20261020/scan.json`; CI publishes its own
head-bound checks and scan artifacts.

Supported release remains blocked on independent security review, pre-registered held-out
and adaptive efficacy evidence, actual application pilots, owner license approval and
target-platform operational recovery/perimeter validation. No external reviewer or pilot
is arranged. No placeholder evidence is supplied, no release validator is weakened, and
no certification or competitive-superiority claim follows from these tests.
