# Action and execution contracts

Use these contracts to connect your application to the enforcement boundary and interpret
its traces. Shared Pydantic models live in `traceguard.types` with contract identifier
`types-v4`. The embedded `SecuredTools` route copies application authority into strict
execution; native integrations use the same `CompiledAuthority` kernel.

For a working integration, start with [application integration](integration.md).

## Authority and proposed calls

`ToolCall` identifies the application task, call ID, tool, arguments, requested resources
and referenced observations. These are proposals; none can authenticate its own scope.
`TaskAuthority` comes from trusted application code. The strict allowlist, exact values,
resource sets, authenticated-source delegations, reviewed generated fields and budget
are compiled with tool schemas and versioned effect descriptors.

Every consequential field needs permission. Generated text fields cannot grant recipients,
object IDs, arbitrary commands or money. Exact JSON equality does not coerce booleans and
numbers. Read adapters need an explicit reviewed schema/resource mapping. Unknown effects,
unknown or invalid schemas, absent fields and changed adapter contracts fail closed.

`Observation` carries an occurrence ID, source ID, trust label and provenance chain.
Model claims about dependencies are not authoritative taint tracking. Retrieved content,
tool output, memory and model explanations cannot grant permission or authenticate a source.

## Decisions, rewrites and execution

`SupervisorOutput` expresses `ALLOW`, `BLOCK`, `ESCALATE` or `REWRITE`, with risk and
bounded reasoning metadata. Contradictory ALLOW decisions (high/critical risk, explicit
policy violation, irrelevant or unnecessary action) escalate before execution. LLM
withholding cannot be discarded by a deterministic allow. Invalid provider responses or
provider failures do not automatically permit work.

A rewrite preserves task/call identity and cannot expand effects, resources or authority.
It is schema-validated and reevaluated through the same boundary. A second rewrite for
the same step escalates. Escalation is terminal for that boundary's task context.
Applications own any later planning or human-approved recovery; TraceGuard does not run
an agent loop or infer renewed authorization from a model explanation.

## Execution plans and containment

`ExecutionPlan` carries the validated effective call, target, container profile, declared
inputs and limits. `SIMULATED` never calls a real handler or reserves a real effect.
Unsupported or unavailable container boundaries withhold execution. Direct filesystem
handlers use descriptor-relative no-follow access, bounded reads and atomic writes;
aliases and special files are rejected. Container staging additionally enforces shared
entry/byte/depth/time budgets before launch.

## Execution outcomes and data release

`TraceEvent.execution_status` distinguishes `not_dispatched`, `dispatched`, `unknown`
and `replayed`. `result_released` records whether agent-visible output was accepted.
`BLOCK_RESULT` means an effect may already have happened and its result was withheld;
it is not an assertion that the effect was prevented. A timeout after invocation leaves
an unknown reservation, preserving its budget and task hold across restart.

## Replay and recovery

Ledger reservations bind the approved execution domain, task, action digest and stable
identity. Accepted results replay only under the same result policy; withheld, missing,
interrupted or policy-changed results remain withheld or require review. Never repeat an
uncertain side effect or silently recreate missing storage. See [ledger lifecycle](ledger_lifecycle.md).

## Post-run and sink decisions

`PostRunAssessment` can accept, block or escalate a result. A rewrite-and-retry assessment
does not automatically redispatch. Agent-visible acceptance does not authorize artifact
publication, a model-provider input or a final answer; those need separate sink permission.
See [data release](data_release.md) and [the security contract](security_framework.md).
