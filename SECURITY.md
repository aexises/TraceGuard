# Security policy

## Supported status

TraceGuard is experimental. No version currently has a supported production release,
response-time SLA or security certification. CI and local conformance establish specific
engineering behavior; independent review, held-out evaluation and application pilots
remain [release requirements](docs/release_assurance.md).

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/aexises/TraceGuard/security/advisories/new)
to report a suspected vulnerability privately. Include:

- The affected commit and integration/deployment profile.
- The trusted and untrusted components involved, including the permission granted.
- A minimal harmless reproduction using disposable state.
- Expected and observed authorization, execution and data-release behavior.
- Relevant redacted traces or receipts, including any uncertain effect.

Keep live credentials, customer data, hidden model reasoning and destructive payloads
out of reports. Coordinate disclosure with the maintainer before publishing sensitive
exploit details. Reports are assessed as capacity permits; there is no bounty or
guaranteed response deadline.

## What to assess

Start with the [security model](docs/security_framework.md) and
[verification map](docs/verification.md). Evaluate the boundary actually deployed:
strict embedded execution trusts the application process; the isolated report profile
adds separate agent, issuer and executor containers. Neither grants safety to raw
callbacks, unreviewed adapters or credential paths that bypass enforcement.

Important areas include authority expansion, schema/default mismatches, tenant/role
confusion, replay and uncertain-effect recovery, result withholding, artifact publication,
provider/final-answer release, certificate identity and private-state access. Use harmless
canaries. Trusted application classification, local storage/fencing and the narrow report
adapter have explicit limits; universal prompt-injection resistance is not claimed.

## Supply-chain checks

CI and weekly workflows scan known dependency advisories and publication-source secrets.
Coverage is limited to resolved dependency profiles on the runner platform and fetched
Git history/source. Scans do not prove upstream integrity, the absence of vulnerabilities
or the removal of secrets from remote objects that were not fetched. Rotate exposed
credentials independently of deleting source. See [release assurance](docs/release_assurance.md).
