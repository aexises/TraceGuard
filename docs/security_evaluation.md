# Effect-grounded evaluation contract

Execution traces separate dispatch status from permission to release results. A withheld
result does not mean an effect was prevented. A post-dispatch failure remains unknown;
unknown effects cannot count as secure completion. Independent evaluators must bind
outcome labels to the actual proposal, execution and provider/effect evidence. Missing
labels remain unknown; a novel action is not automatically classified as unsafe.

The application or external evaluation runner supplies complete trace-bound outcomes.
This package validates a frozen protocol and analyzes those records; it does not execute
models or plan agent actions. Task-family clustering keeps repeated seeds within the same
independent unit and gives families equal weight in paired uncertainty.

Before a held-out comparison with CaMeL/Progent or a strict/hybrid study, freeze a protocol:

```bash
python -m traceguard.validation.security_evaluation --output artifacts/study/protocol.json freeze \
  --config configs/my-study.json
python -m traceguard.validation.security_evaluation --output artifacts/study/report.json analyze \
  --protocol artifacts/study/protocol.json --results artifacts/study/outcomes.jsonl
```

The protocol schema pins dataset/arm/evaluator source commits, model settings and executor
contract digests, explicit baseline, task-to-family mapping, disjoint declared development
families, seeds, adaptive-query budget, tool calls and model tokens. Commit the frozen file
before final runs and preserve it externally. Every arm/task/seed outcome is required;
failed/outage/escalated episodes cannot be omitted. Outcomes must match the configuration
and resource budgets and reference hash-verified trace and effect-evidence files. Analysis
reports secure completion, protected releases, unknown effects, review workload and actual
cost/latency, with family-clustered paired uncertainty. Unknown effects cannot count as
secure completion. No protocol/result is silently overwritten.

Use `Protocol.model_json_schema()` and `Outcome.model_json_schema()` from
`traceguard.validation.security_evaluation` to generate input schemas. Tests use synthetic records
solely to validate accounting and rejection paths; they are not new efficacy measurements.

The tool checks consistency, completeness and evidence binding. It does not certify the
truth of submitted outcome labels, independence of the held-out families, equivalence of
external executor integrations or the quality of adaptive attackers. Those require native
effect evaluators, frozen code/configuration and independent review. Synthetic unit fixtures must not be relabelled as an upstream reproduction, efficacy
measurement or superiority result.

External work still required: select compatible native tasks/attacks and baseline commits,
arrange independent held-out/adaptive evaluation, run paid providers only with an approved
budget, and conduct two real application pilots. No such pilots or reviewers are currently
arranged. The local mTLS/Docker integration canaries are separate engineering evidence.
