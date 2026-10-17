# Security policy

TraceGuard is an experimental security framework. There is currently no supported
production release or response-time SLA. Passing CI is implementation evidence;
independent security review, held-out adversarial evaluation and real application
pilots remain required before a supported release.

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/aexises/TraceGuard/security/advisories/new).
Private reporting is enabled for this repository. Include the affected commit,
deployment profile, trust assumptions, harmless reproduction, expected/observed
effects and relevant redacted traces. Do not include live credentials, customer
data, hidden model reasoning or destructive payloads. Use disposable fixtures.

The maintainer will assess reports as capacity permits. There is no bounty or
guaranteed response deadline. Coordinate disclosure with the maintainer; do not
publish sensitive exploit details in a public issue while a report is unresolved.

Use the strict, isolated execution profile for security evaluation. Research-mode
ablations, application-owned classification labels, local SQLite backup/fencing,
and the narrow report adapter have explicit limitations in
[the security completion record](docs/security_completion.md). This repository does
not establish a universal prompt-injection defense or unrestricted connector safety.

Dependency and publication-source secret scans run in CI and weekly. The scans cover
known package advisories for the runner platform and fetched repository history;
they cannot prove absence of vulnerabilities, previously removed remote objects,
or compromised upstream packages. See [release assurance](docs/release_assurance.md).
