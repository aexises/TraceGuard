# TraceGuard

TraceGuard is a research platform for evaluating and enforcing safeguards around
tool-using AI agents. It has two complementary components:

- a reproducible research runtime for testing system-prompt defenses, deterministic
  policy, LLM supervision, and Docker containment; and
- a safety control plane for evaluating agent and model actions against versioned policy
  before a mediated side effect is allowed.

It is made for researchers and engineers who need to study prompt injection and unsafe
tool use, compare defense configurations, or build a policy-enforced boundary around
agent actions. TraceGuard is not a general-purpose agent framework and does not make an
unmediated agent safe by itself.

## Independent-project milestone

The policy audit is in [`docs/policy_review_20261006.md`](docs/policy_review_20261006.md).
The implementation and local pilot follow-up is in
[`docs/hardening_and_pilot_20261006.md`](docs/hardening_and_pilot_20261006.md).
Active contracts are `types-v3`, custom policy `2.0.0`, `effects-v1`, and supervisor
`supervisor_v2.txt`. Historical custom results use older enforcement and the heuristic
surrogate; they do not demonstrate incremental live-supervisor value.

The current primary outcome is secure task completion. Missing authority and provider
failures stop with `ESCALATE`; confirmed `BLOCK` permits at most two generic replans.

```bash
# Frozen 30 attacked + 30 authorized synthetic snapshot cases, then 12 matched live cases.
# Each live case runs once under D and D+LLM (24 episodes); tools are disposable simulations.
python -m benchmarks.semantic_pilot --model qwen3:1.7b --live \
  --output artifacts/semantic_pilot_new_run

# Inspect the native evaluation configuration before a larger run.
python -m traceguard.conclusion_ablation --dry-run \
  --agent-model qwen3:1.7b --supervisor-model qwen3:1.7b \
  --output-dir artifacts/conclusion_new_protocol
```

Use a fresh output directory for each pilot. Its cases are development fixtures inspired
by injection research, not a reproduction of an upstream benchmark. Native conclusion
runs use a minimal research mode with task-specific correction/answer fallbacks disabled.
Resolved prompts and hashes are saved with native runs. The vulnerable-agent flag is
identical for clean and attacked runs and remains a separately labelled stress test.

## Prerequisites

The local runtime requires Python 3.11 or newer, `git`, and `pip`. Docker is optional
and is required only for containment checks and container execution. Gemini, AgentDojo,
and external dataset integrations are optional extras. The control-plane Kubernetes
deployment additionally requires Kubernetes 1.27+ and a container registry.

See [setup.md](setup.md) for installation, optional integrations, verification,
experiments, Docker execution, benchmarks, API development, and deployment guidance.
Use the locked installation route there for release checks. The Kubernetes template is
single-replica development only; production persistence and identity adapters remain required.
`traceguard release-validate --base-image "$PYTHON_IMAGE" --release-image "$TRACEGUARD_IMAGE"`
checks references; add `--output-manifest artifacts/release/control-plane.yaml` to write a
new manifest. Follow the separate registry and Kubernetes-schema gates in
[the container release guide](docs/control_plane.md#container-build-and-release-checks).

## How it works

For each proposed tool call, TraceGuard combines structured tool definitions,
deterministic policy checks, and an optional supervisor. The policy can allow, block,
escalate for review, or safely rewrite a call. Untrusted evidence and sandbox output
remain bounded inputs to the decision process; they never become host-shell commands.

When an uncertain command is eligible for containment, TraceGuard executes it only in a
configured Docker profile. Profiles use immutable images and fixed resource and isolation
limits. Failure to verify the environment, image, output, or cleanup fails closed.

The control plane applies the same decision model at a versioned HTTP boundary. It
evaluates an action before the caller performs it, records an auditable decision, and can
issue signed, tenant-scoped policy bundles for limited offline authorization. Only explicit,
matching `ALLOW` rules may authorize execution; unknown, stale, unavailable, or
unreviewed actions are blocked or escalated.

## Documentation

- [Setup and operations](setup.md)
- [Policy contracts](docs/contracts.md)
- [Supervisor calibration](docs/supervisor_calibration.md)
- [Control-plane design](docs/control_plane.md)
- [Evaluation report](docs/evaluation_report.md)
- [Demo walkthrough](docs/demo.md)
- [External benchmark guidance](docs/external_benchmarks.md)
