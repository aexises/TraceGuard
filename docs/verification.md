# Verify an integration and release candidate

Use this map to identify the maintained checks for each security contract. Run against
the candidate being reviewed and retain its exact revision, configuration and evidence.
Prior results do not validate changed code. Engineering checks do not replace independent
review or application pilots.

## Contract coverage

| Contract | Maintained regression coverage |
| --- | --- |
| Atomic, freshly authorized registration | `tests/test_authority_storage.py` |
| Identified ledgers; restart-safe task holds; fenced migrations | `tests/test_ledger_lifecycle.py`, `tests/test_embedded_effects.py` |
| Separate durable execution and result disposition | `tests/test_result_disposition.py`, `tests/sandbox/test_docker_canaries.py` |
| Strict field/resource scope and common read mappings | `tests/policy/test_strict_kernel.py`, `tests/policy/test_strict_modes.py`, `tests/policy/test_read_resources.py` |
| Native Inspect dispatch, stable IDs, budget/unknown/replay semantics | `tests/test_inspect_execution.py`, `tests/test_inspect_compatibility.py` |
| Complete atomic artifact publication and recovery | `tests/test_artifact_recovery.py`, `tests/test_release_gate.py` |
| Exact mTLS peer identity and bounded total ingress | `tests/test_mtls_executor.py`, `tests/test_mtls_ingress.py` |
| Signed policy cache, tenant scope, deny precedence and audit integrity | `tests/test_cache_and_audit_security.py`, `tests/test_control_plane.py` |
| Bounded filesystem collection and container staging | `tests/tools/`, `tests/sandbox/` |
| Schema/rewrites, provider failure and contradictory decisions | `tests/test_hardening.py`, `tests/test_execution_invariants.py`, `tests/supervisor/` |
| Complete externally supplied outcome protocols and evidence binding | `tests/test_security_evaluation.py` |
| Immutable deployment references and authentic release evidence requirements | `tests/test_release.py`, `tests/test_release_assurance.py` |

## Local and container validation

Run the full suite, Ruff and package build using [setup](../setup.md). Docker cases are
opt-in and use harmless canaries with disposable state. The three-container conformance
command checks authorized report publication, denied bypasses, replay, issuer restart,
role/key separation and an external TCP denial. Readiness probes wait for listeners before
application requests; they never retry a possibly dispatched consequential action.

## Supply-chain and artifact validation

Generate current advisory reports, redacted secret scan results and CycloneDX SBOMs with
`python -m traceguard.validation.release_checks --output artifacts/security`. Both product
profiles (core and all extras) must finish successfully. Scanner/network failure is a
failure, not clean evidence. Registry advisory coverage is not an upstream source audit.

A fresh source digest must accompany release review. Code, adapter, schema, lock or workflow
changes invalidate older evidence. Installed-wheel checks must run outside the checkout;
container conformance must use a source-matching adapter image. Local ARM64 execution does
not establish Linux/AMD64 behavior; CI and each supported target need their own validation.

## Outstanding supported-release gates

- Independent review of the exact candidate, with findings resolved and identities verified.
- Independently labeled held-out/adaptive evaluation with frozen budgets and native effect
  outcomes under compatible baseline conditions.
- Two distinct real application pilots, with operator intervention, recovery, utility and
  actual prohibited effects/data releases recorded.
- Owner-approved distribution license and rights to contributed source.
- Target-platform identity/key custody, fencing, backup recovery, credential/egress isolation
  and transport perimeter validation.

No independent review, real application pilot or external efficacy result is established
by this coverage map. Follow [release assurance](release_assurance.md) for the evidence schema
and manual candidate workflow. This guide is engineering documentation, not certification.
