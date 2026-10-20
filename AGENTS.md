# Repository guidelines

TraceGuard is a security framework for application-owned agent actions. Application code
owns planning and model conversations; this repository provides policy, enforcement,
authority, execution, isolation and release boundaries.

## Structure

- `src/traceguard/control/`: tenant admission, policy, signed authority and persistent state.
- `src/traceguard/policy/`: deterministic grants, schemas, effects and resource mappings.
- `src/traceguard/security.py`: public embedded `SecuredTools` entry point.
- `src/traceguard/_enforcement.py`: private strict execution implementation, without an agent loop.
- `src/traceguard/integrations/`: reviewed native application adapters.
- `src/traceguard/sandbox/` and `tools/`: bounded execution and confined tool handlers.
- `src/traceguard/validation/`: release evidence, scans, isolated conformance and external outcome analysis.
- `tests/`: positive, denial, boundary, concurrency, restart and recovery regressions.
- `docs/`: current contracts and operating guidance; generated evidence belongs in ignored `artifacts/`.

## Commands

Use Python 3.11+, `uv==0.13.1` and the committed lock. Bootstrap build dependencies with
`uv sync --locked --extra dev --no-install-project`, then install the package with
`uv sync --locked --extra dev --no-build-isolation --no-editable`.

Run `python -m pytest`, `ruff check .`, `ruff format --check .` and
`python -m build --no-isolation`. Run installed-wheel smoke outside the checkout.
Docker tests require the pinned image and `TRACEGUARD_RUN_DOCKER_TESTS=1`.
Document operational commands in `setup.md`; use package modules or CLI entry points.

## Security invariants

Use typed, versioned contracts and mandatory strict application authority. Model output
and untrusted content cannot grant permission. Every rewrite passes the same checks.
Preserve durable reservations, uncertainty and result withholding across restart.
Never recreate missing ledgers, blindly repeat uncertain effects, weaken release-evidence
gates or invent external review/pilot/license approval. Keep provider credentials out of
source and logs. Use harmless canaries and disposable state; do not call real providers
or perform destructive host effects in tests.

## Changes and verification

Inspect existing code before editing, preserve unrelated work and use scoped imperative
commits. Explain behavior/interface changes and security impact in PRs. Cover normal,
denial and failure paths; report exactly which checks ran and their limitations. Green
CI is engineering evidence, not production certification or independent security review.
