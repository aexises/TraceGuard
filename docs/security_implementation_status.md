Security implementation status — 17 October 2026
=================================================

The first ten dependency-ordered implementation changes from the audit are implemented.
They are reviewable changes, not a declaration that every production release gate is met.
Merge/review in order; later branches depend on earlier security contracts.

| Change | Review | Implemented behavior |
| --- | --- | --- |
| Tenant identity scope | [PR 9](https://github.com/aexises/TraceGuard/pull/9) | Explicit tenant membership and operation scope before service state access |
| Decision receipts | [PR 10](https://github.com/aexises/TraceGuard/pull/10) | Principal/task/action/policy-bound idempotency; stale and conflicting receipts rejected |
| Email effects | [PR 11](https://github.com/aexises/TraceGuard/pull/11) | CC/BCC/attachment authorization and versioned sink extraction |
| Objects and read egress | [PR 12](https://github.com/aexises/TraceGuard/pull/12) | Explicit object/URL scope, sensitive-read grants and exact JSON comparisons |
| HTTP execution | [PR 13](https://github.com/aexises/TraceGuard/pull/13) | Structural scope, public DNS/IP checks, TLS hostname verification, no redirects, bounded responses |
| Final execution invariants | [PR 14](https://github.com/aexises/TraceGuard/pull/14) | No real simulation effects; contradictory ALLOW decisions withheld across integrations |
| Filesystem/context isolation | [PR 15](https://github.com/aexises/TraceGuard/pull/15) | No-follow/hardlink-resistant direct reads, atomic writes and isolated runtime authority |
| Strict deterministic kernel | [PR 16](https://github.com/aexises/TraceGuard/pull/16) | Explicit compiled grants; complete consequential fields; shared conformance and deny precedence |
| Cache/audit trust | [PR 17](https://github.com/aexises/TraceGuard/pull/17) | Public-key verification, audience/epoch limits, explicit-rejection handling and audit-v2 privacy/integrity |
| Execution/review lifecycle | [PR 18](https://github.com/aexises/TraceGuard/pull/18) | Signed grants, action-bound approvals, adapter binding, mandatory online checks and durable SQLite reservations |

**Deterministic policy assessment**

The earlier policy is not a no-op: it performs meaningful schema, path, repeat, amount
and exact-constraint checks. Its English grammar is insufficient as an authorization
root. The legacy research interface remains labelled as such; use `SecuredTools` or
strict registered execution grants for explicit permission enforcement.

`python -m benchmarks.policy_conformance` compares the current research grammar and
strict grants on ten authored development cases: 4/10 versus 10/10 expected decisions.
Authorized cases remain allowed. These are implementation regressions, not a held-out
security estimate or evidence of outperforming CaMeL/Progent. The reference comparison
and the required matched study are in `docs/security_framework.md`.

**Verification executed**

- Locked development/AgentDojo environment synchronized using uv 0.13.1, and the final
  package reinstalled with the documented locked, non-editable, no-build-isolation route.
- Complete suite with `TRACEGUARD_RUN_DOCKER_TESTS=1`: **383 passed, no skips**. Includes
  the real loopback API test and all seven disposable Docker canaries on local ARM64.
  The pinned image was absent initially; fetched its exact digest, then reran successfully.
- Ruff lint/format checks and `git diff --check` passed.
- Source distribution and wheel builds passed. Installed-package imports, bundled effect
  descriptors, strict calculator execution and development conformance passed from `/tmp`.
- `uv lock --check --offline` passed with a writable disposable cache.
- Native provider efficacy, full external benchmarks, advisory scanning, live public HTTPS
  services and independent penetration testing were not performed.

**Audit disposition and explicit limits**

S01–S08, S11, S13, S15 and S16 have direct regression coverage for their demonstrated
failures in the supported paths. S09 replaces distributed signing secrets with public
verification and separated purposes; production KMS/rotation remains open. S10 now
refuses client claims of trusted evidence, while authenticating sources remains an
integration requirement. The execution issuer refuses delegation without a source adapter.
S12 redacts recognized structured credentials; it is not arbitrary-secret detection.
S14 explicitly bounds read-only offline grants; immediate offline revocation is not promised.

The executor ledger is durable local state, but issuer policies/tasks/reviews/keys remain
development memory state. Agent/executor credential, process and egress isolation must be
enforced by deployment. Unknown effects need authoritative provider reconciliation; there
is no global exactly-once guarantee. Sandbox disk/inode quotas, safe bounded staging,
quarantine and general output/model-provider release controls remain open. Maintain all
remaining release gates in `docs/security_framework.md` rather than marking them complete
because these PRs or their tests pass.
