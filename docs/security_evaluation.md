# Evaluate security using actual effects

Use this protocol to assess whether an application completed its authorized task while
preventing prohibited effects and data release. TraceGuard validates a frozen protocol
and analyzes externally supplied outcomes. It does not run models, plan actions or
supply a native external benchmark runner.

## Define the comparison before running it

Freeze compatible tasks, attacks, models, privileges and budgets. The protocol pins
source commits for datasets, arms and evaluators; model settings; executor contract
digests; an explicit baseline; task-to-family mapping; declared disjoint development
families; seeds; adaptive-query budgets; tool calls and model tokens.

For a deterministic/hybrid comparison or an external CaMeL/Progent comparison, first
check that execution privileges and outcome evaluators are compatible. A different
model, task budget or effect boundary can invalidate the comparison.

```bash
python -m traceguard.validation.security_evaluation \
  --output artifacts/study/protocol.json freeze --config configs/my-study.json
```

Supply your study configuration; `configs/my-study.json` is an application-owned input,
not a bundled benchmark. Generate input schemas with `Protocol.model_json_schema()`
and `Outcome.model_json_schema()` from `traceguard.validation.security_evaluation`.
Commit the frozen protocol before final runs and preserve it independently.

## Collect complete effect evidence

For every arm/task/seed, record the proposal, dispatch status, result-release decision,
actual effect evidence, budgets, cost and latency. Include failures, outages and
escalations. Outcomes must match the frozen configuration and reference hash-verifiable
trace and effect-evidence files.

A withheld result does not prove prevention: an effect may have occurred before output
was blocked. Post-dispatch failures remain unknown and cannot count as secure completion.
Missing labels remain unknown; novel actions are not automatically unsafe. Independent
labels must refer to actual effects, not a model's self-assessment.

## Analyze the frozen records

```bash
python -m traceguard.validation.security_evaluation \
  --output artifacts/study/report.json analyze \
  --protocol artifacts/study/protocol.json --results artifacts/study/outcomes.jsonl
```

Analysis checks completeness, configuration/budget consistency and evidence hashes.
It reports secure completion, protected releases, unknown effects, review workload and
actual cost/latency. Paired uncertainty clusters repeated seeds within task families
and weights families equally. Existing protocol/report files are not silently overwritten.

## Interpret the result within its scope

The analyzer cannot establish label truth, independence of held-out families, equivalence
of external executor integrations or adaptive attacker quality. Those require native
effect evaluators, frozen code/configuration and independent assessment. Synthetic test
records validate accounting and rejection paths; they are not efficacy measurements,
upstream reproductions or evidence of superiority.

External held-out/adaptive evaluation and two real application pilots remain
[release requirements](release_assurance.md). No reviewers or pilots are currently
arranged. Paid provider runs need an approved budget. Local mTLS/Docker canaries remain
separate engineering evidence.
