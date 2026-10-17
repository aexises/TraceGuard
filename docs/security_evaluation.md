# Effect-grounded evaluation contract

Runtime traces now record dispatch status independently of result release. BLOCK_RESULT
means a command executed and its result was withheld. Post-dispatch exceptions are unknown;
they are not proof of prevented effects. ReAct stops on execution uncertainty. Positive
execution checks do not accept uncertain calls, while negative forbidden-execution checks
withhold when that call may have executed. Historical traces without the new fields retain
a conservative outcome-based fallback.

Call labels require exact known fixtures, an explicit forbidden-call predicate or independent
`CallEvidence` bound to the complete proposal digest. A novel/alternative plan is unlabeled,
not automatically unsafe. Reports contain only actually proposed calls; they do not invent
missing calls to match a scripted plan. Primary utility/security remain native state and
output predicates. Post-run accuracy requires independent evidence-level acceptance labels,
not the episode's overall security result. Label coverage is reported; unknown effects are
not assigned false safety labels. Overall unsafe-effect prevention/rate is unavailable when
any unsafe call lacks effect evidence. Tool-call accuracy applies only to labelled reference
calls and must be read alongside its coverage, not as general live-planner accuracy.

Custom paired uncertainty resamples case IDs, keeping repeated seeds within the same unit.
The dedicated external protocol supports declared task-family clustering and equal-family
paired deltas, rather than treating repeated seeds as independent tasks.

Before a held-out comparison with CaMeL/Progent or a strict/hybrid study, freeze a protocol:

```bash
python -m benchmarks.security_evaluation --output artifacts/study/protocol.json freeze \
  --config configs/my-study.json
python -m benchmarks.security_evaluation --output artifacts/study/report.json analyze \
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
`benchmarks.security_evaluation` to generate input schemas. Tests use synthetic records
solely to validate accounting and rejection paths; they are not new efficacy measurements.

The tool checks consistency, completeness and evidence binding. It does not certify the
truth of submitted outcome labels, independence of the held-out families, equivalence of
external executor integrations or the quality of adaptive attackers. Those require native
effect evaluators, frozen code/configuration and independent review. The ten development
conformance cases and earlier scripted/pilot numbers remain development evidence; they
must not be relabelled as an upstream reproduction or superiority result.

External work still required: select compatible native tasks/attacks and baseline commits,
arrange independent held-out/adaptive evaluation, run paid providers only with an approved
budget, and conduct two real application pilots. No such pilots or reviewers are currently
arranged. The local mTLS/Docker integration canaries are separate engineering evidence.
