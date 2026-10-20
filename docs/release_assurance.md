# Release assurance and outstanding owner decisions

The current status is **experimental, no supported production release**. No
independent reviewer or application pilot has been arranged. No distribution license
has been selected. The release-candidate workflow deliberately fails without their
evidence; no tag, package publication or automatic promotion is configured.

## Repeatable local checks

Use the locked development environment, install `uv==0.13.1`, and fetch full Git
history. From the checkout run:

```sh
python -m traceguard.validation.release_checks --output artifacts/security
python -m traceguard.validation.release_assurance --digest-only
python -m traceguard.validation.release_assurance
```

The first command verifies the pinned Gitleaks archive SHA-256 before extraction,
scans all fetched refs and non-ignored publication source with full redaction,
exports hash-pinned core/all-extra requirements and runs pinned pip-audit with no
dependency installation. Any scanner, integrity, size-limit, advisory or secret
finding failure stops the check. Ignored local credentials are outside the source
publication scan. No test/source blanket exemptions are supplied. `scan.json` is
created only after every scan passes. JSON advisories and CycloneDX dependency SBOMs
are retained. SBOMs describe resolved dependencies, not every file in an artifact.
The product has no native benchmark VCS environment. Registry advisory checks cover
its distributed dependency profiles; they are not upstream source-code audits.

Sources: [pip-audit](https://github.com/pypa/pip-audit),
[Gitleaks](https://github.com/gitleaks/gitleaks), and
[GitHub attestations](https://github.com/actions/attest/tree/v4).
Known-advisory scanning is time/platform bounded; run on each supported platform
before promotion. Pinning the scanner version does not independently establish the
trustworthiness of its own transitive tool dependencies.

## Owner license decision

The owner must select a license, confirm the right to license contributed code,
add the complete `LICENSE`, and set matching package metadata. This work does not
grant new rights. Consider the actual
[Apache 2.0 terms](https://www.apache.org/licenses/LICENSE-2.0) or
[MIT terms](https://opensource.org/license/mit); do not treat this paragraph as
license approval. Until selection, `license-approval` evidence is missing.

## External review packet

Give a reviewer this branch's source digest, exact commit, threat model, maintained verification guide,
test logs, isolated-executor canary, dependency reports and SBOMs. Ask an
independent reviewer to reproduce bypass/replay/uncertainty/restart/rotation/data
release tests and inspect the trust boundaries. Record reviewer identity and
affiliation, scope/exclusions, methodology, findings, reproductions, fixes and
unresolved blockers. Re-review changed governed source. A self-authored checklist
does not constitute independent review.

Recruit two distinct application organizations. Start with disposable data and
minimal side-effect permissions; run one read/report application and one real
provider integration only after that provider has a typed, receipt-verifiable
adapter. For each pilot record owners, deployment identity, grant/approval flows,
benign utility, prohibited effects, data release, unknown-outcome recovery,
false blocks, latency/cost, operator interventions and unresolved incidents.
The existing report canary is local integration validation, not either pilot.

Use the [evaluation protocol](security_evaluation.md) for independently labeled,
held-out/adaptive tests against an explicit matched deterministic baseline and
relevant external systems under compatible conditions. Set acceptance criteria
before measurement. Do not claim superiority from synthetic fixtures.

## Evidence envelope and workflow

After actual work, add `configs/release_evidence.json` with these fields:
`source_digest`, `reviewed_revision` (40-hex), `maintainer_organization`,
`license_spdx`, `license_sha256`, and `evidence`.
Each evidence record contains `kind`, `organization`, `accountable_person`,
`source_digest`, `reference` (a traceable HTTPS record), `path` (a repository-relative
report), `sha256`, `accepted: true`, and `unresolved_blockers: 0`.
Required kinds are `independent-review`, `heldout-evaluation`, `license-approval`,
and two `pilot` records from distinct organizations. Duplicate reports/references,
same-organization review, missing documents, changed hashes or source mismatches
fail. Never add placeholder positive records to satisfy this gate.

The digest binds source, tests, configuration data, workflows and build
inputs, excluding only the envelope itself, caches and compiled Python. Evidence
reports and license are separately hash-bound. `reviewed_revision` is traceability
metadata; digest equality establishes content binding, not the reviewer's identity.
The validator checks document integrity and maintainer assertions. A trusted owner
must verify identities, independence, evaluation validity and pilot results. No
JSON schema or hash proves that external work occurred.

The manual main-only candidate workflow checks evidence, lint/tests including
Docker canaries, scans, package build and isolated integration before attesting
wheel/sdist provenance and dependency SBOMs. It uploads candidate artifacts and
checksums, without publishing a supported release. Its signing path cannot be
exercised honestly until the missing external evidence and owner decisions exist.
Protect the default branch and review changes to release gates/workflows before
using it for distribution. Configure organizational reviewers and deployment
approvals when maintainers are available; none are fabricated here.
