# Release assurance

TraceGuard has no supported production release. No independent reviewer or application
pilot is currently arranged, and no distribution license has been selected. The manual
candidate workflow intentionally refuses promotion without authentic evidence. It does
not publish a package, create a release tag or automatically promote a candidate.

## Promotion requirements

| Gate | Required evidence |
| --- | --- |
| Engineering validation | Candidate-bound tests, container conformance, installed-wheel checks, scans and build artifacts |
| Independent security review | Identified independent reviewer, exact scope/revision, reproducible findings and no unresolved blockers |
| Held-out evaluation | Frozen compatible baseline/arms, independently labeled effects, complete outcomes and prespecified acceptance criteria |
| Application pilots | Two distinct real application organizations with utility, prohibited effects, release and recovery evidence |
| License approval | Owner-selected license, contribution rights, complete `LICENSE` and matching package metadata |
| Deployment validation | Target identity, key custody, private state, fencing/recovery and network/transport boundary checks |

Automated checks enforce document structure and integrity. An accountable owner must
verify that external work occurred and that identities, independence and outcomes are
credible. Hashes and positive JSON fields cannot establish those facts.

## Generate engineering evidence

Use the locked development environment and fetch complete Git history. Run:

```bash
python -m traceguard.validation.release_checks --output artifacts/security
python -m traceguard.validation.release_assurance --digest-only
python -m traceguard.validation.release_assurance
```

The scan runner verifies the pinned Gitleaks archive hash before extraction, then scans
fetched refs and non-ignored publication source with full redaction. It exports hashed
core/all-extra requirements and runs pinned pip-audit without installing dependencies.
Scanner failure, integrity/size-limit failure, a secret finding or an advisory stops the
check. `scan.json` is written only after every scan succeeds. Retain the advisory JSON
and CycloneDX dependency SBOMs; they describe dependencies, not every artifact file.

Ignored credentials and unfetched remote objects are outside the publication-source
scan. Known-advisory checks are platform/time bounded and do not audit upstream source.
Run them on each supported platform before promotion. Scanner version pins do not prove
the trustworthiness of the scanner's own transitive dependencies.

Tool references: [pip-audit](https://github.com/pypa/pip-audit),
[Gitleaks](https://github.com/gitleaks/gitleaks),
[GitHub attestations](https://github.com/actions/attest/tree/v4).
See [verification](verification.md) for the complete engineering coverage map.

## Prepare external review and pilots

Give the reviewer the candidate's source digest, exact commit, [security model](security_framework.md),
verification guide, test logs, isolated-executor canary, advisory reports and SBOMs.
Require explicit scope/exclusions, methodology, reviewer identity/affiliation, findings,
reproductions, fixes and unresolved blockers. Include authority bypass, replay,
uncertainty, restart, rotation and release boundaries. Changed governed source needs
new content-bound review; a maintainer checklist is not independent review.

For two distinct application organizations, start with disposable data and narrow
permissions. A read/report application can use the existing surface; a real provider
integration first needs a typed, receipt-verifiable adapter. Record accountable owners,
deployment identity, approvals, benign utility, actual prohibited effects/data releases,
unknown-outcome recovery, false blocks, latency/cost and operator interventions.
The local report canary does not count as either pilot.

Use the [external evaluation protocol](security_evaluation.md) to freeze matched
baselines, budgets and independently labeled held-out/adaptive tests. Define acceptance
criteria before measurement. Synthetic fixtures cannot establish comparative efficacy.

## Approve distribution rights

The owner must select a license, confirm rights to contributed code, add the complete
`LICENSE` and update package metadata consistently. No license is selected by this guide.
Review actual [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or
[MIT](https://opensource.org/license/mit) terms if considering those options.
Until approval, `license-approval` evidence remains absent.

## Assemble the evidence envelope

After the work is complete, add `configs/release_evidence.json` with:

- `source_digest`, `reviewed_revision` (40 hexadecimal characters) and `maintainer_organization`.
- `license_spdx` and `license_sha256`.
- `evidence`, containing the records below.

Each record requires `kind`, `organization`, `accountable_person`, `source_digest`,
`reference` (a traceable HTTPS record), `path` (repository-relative report), `sha256`,
`accepted: true` and `unresolved_blockers: 0`. Required kinds are `independent-review`,
`heldout-evaluation`, `license-approval` and two `pilot` records from distinct organizations.
Duplicate reports/references, same-organization review, absent documents, changed hashes
and source mismatches fail. Never insert placeholder success records.

The source digest covers source, tests, configuration, workflows and build inputs,
excluding the evidence envelope itself, caches and compiled Python. Reports and license
are separately hash-bound. `reviewed_revision` provides traceability; content binding
comes from digest equality. Identity and evaluation validity remain owner checks.

## Run the candidate workflow

The manual main-only workflow checks evidence, lint, tests including Docker canaries,
scans, package build and isolated integration before attesting wheel/sdist provenance
and dependency SBOMs. It uploads candidate artifacts and checksums without publishing
a supported release. Missing external evidence must continue to stop this path.

Protect the default branch and review changes to release gates/workflows. Configure
organizational reviewers and deployment approvals when accountable maintainers are
available. Passing engineering checks alone cannot satisfy the external gates.
