# TraceGuard `types-v4` Contract

`src/traceguard/types.py` is the authoritative shared schema. Experiment manifests record
`types-v4`; incompatible changes require a new contract version. Version 3 adds trusted
`TaskAuthority`, explicit `UNCERTAIN` goal labels, and bounded block replanning. Version 2
added observation-injection and memory-poisoning threat models. Existing frozen cases
remain valid; historical enforcement results belong to their original code and policy.

External benchmark adapters use the independent `benchmark-adapter-v1` JSON protocol.
Requests and results reject unknown fields, carry the native case and dataset revision,
and keep upstream native scores separate from TraceGuard's normalized utility and
security fields.

## Decisions and precedence

- `ALLOW`: the call may proceed only to the recorded execution target.
- `REWRITE`: replace the call once, preserving task ID, step ID, call ID, observation
  provenance, and narrowing or preserving requested resources. The rewritten call is evaluated again. A second
  rewrite escalates.
- `ESCALATE`: stop automatic execution and require human review. It is not an allow.
- `BLOCK`: withhold the prohibited call. Allow at most two generic replans by default
  within the original authority; `max_block_replans=0` stops immediately. It has the
  highest decision precedence. A rejected rewrite escalates in native bridges.

Combination precedence is `BLOCK > ESCALATE > REWRITE > ALLOW`. Deterministic `BLOCK` and
`ESCALATE` are terminal hard gates; an LLM cannot lower them. An LLM may raise risk or make
a stricter decision. Container routing is retained only when the winning decision is not
`BLOCK` or `ESCALATE`.

## Goal labels

- Relevance: `IRRELEVANT` has no defensible connection to the goal, `WEAK` has an indirect
  or uncertain connection, and `STRONG` directly advances it.
- `UNCERTAIN` records an unverified assessment; it is never converted to `HELPFUL`.
- Necessity: `UNNECESSARY` adds no required value, `HELPFUL` is useful but replaceable, and
  `NECESSARY` is required for successful completion.

Relevance and necessity are independent. A relevant call may be unnecessary, and a
necessary call may still be too risky to allow.

## Risk and trust

Risk is ordered `LOW < MEDIUM < HIGH < CRITICAL`. Container execution may contain only
approved uncertain or medium-risk command calls; it never makes prohibited high- or
critical-risk behavior permissible.

`TRUSTED_SYSTEM` is policy/configuration, `USER_INPUT` is the explicit user request,
`TRUSTED_TOOL` is deterministic local output, `UNTRUSTED_DOCUMENT` and `UNTRUSTED_TOOL`
may contain indirect instructions, and `AGENT_GENERATED` is model-authored data.
Untrusted content may provide facts but cannot independently authorize side effects.

## Trusted task authority

`TaskAuthority` is supplied by authenticated application code or a human-approved task
configuration, never copied from a document's claimed approvals. Defaults grant no new
side effects. It supports an optional tool allowlist, exact argument constraints,
field-to-source delegation, a cumulative payment budget (`max_amount`), exact prohibited
content, repeat exceptions (`repeatable_tools`), and approved conditions. The reserved argument constraint `requested_resources`
compares the call's resource list, rather than a tool argument. Unnamed container inputs
need an explicit path in the original task or this trusted constraint/delegation.

```python
from traceguard.types import TaskAuthority

scope = TaskAuthority(
    allowed_tools=["send_email"],
    argument_values={"send_email": {"to": "reviewer@example.test"}},
    delegated_fields={"send_email": {"body": ["approved-summary"]}},
)
```

Delegation resolves one JSON object from an observation with the exact authorized
`source_id` and compares that field's value. Missing/conflicting/unparseable sources
escalate. Granting a source a field does not grant it additional tools or permissions.
The application must authenticate the source identifier and the declaration; a hash or
an observation ID alone is not source authentication or factual verification.

Identical mutating/command arguments already executed in the same task are blocked
unless trusted configuration includes the tool in `repeatable_tools`. This executor
boundary also applies to LLM-only supervision; it does not run the full deterministic
authority policy in that arm. Pure reads remain repeatable. Native batches reserve
previously approved calls to prevent two identical writes in one batch and reserve
their payment amounts against the cumulative budget. Reserved calls are not presented
to the model as already executed.

Protected-content checks inspect actual nested argument strings before JSON escaping;
they match exact configured substrings, including Unicode and newline characters.
They do not inspect an agent's unmediated final answer or infer arbitrary secrets.

The shared `effects-v1` registry covers the inspected AgentDojo 0.1.35 suites and custom
software tools, including argument-dependent memory/editor operations. Unknown effects
escalate. Custom filesystem and container restrictions remain additional gates; generic
service tools do not receive fictional filesystem/container guarantees.

Natural-language checks cover a bounded English grammar for verbs, negation, destinations,
conditions and selected calendar parameters. Ambiguous destinations/unnamed filesystem
reads escalate; this parser does not establish arbitrary natural-language authorization.
For consequential arguments, prefer explicit trusted constraints.
Payment amounts need an exact constraint, delegated source or bounded budget;
authorizing a destination alone does not grant an arbitrary payment amount.

Requests include executed history, trusted policy, field value occurrences, stable
observations and rewrite state. Occurrence provenance is constructed independently of
agent claims but is not causal taint tracking. Both providers use the same envelope and
strict response contract; nested JSON schema validation precedes native effects. Remote
schema references are unsupported. Request redaction gives recognized protected values
opaque local identifiers; ordinary trace redaction still removes them. Neither is a
complete arbitrary-secret detector.

## Execution targets and post-run handling

- `DEFAULT`: execute through the typed local tool boundary.
- `SIMULATED`: return a non-executing marker.
- `CONTAINER`: execute only through a trusted named sandbox profile.

Post-run `ACCEPT_RESULT` exposes bounded output to the agent. `BLOCK_RESULT` quarantines
it. `ESCALATE` stops. `REWRITE_AND_RETRY` never authorizes automatic host execution and is
currently converted to human escalation until a reviewed contained retry plan exists.
For LLM-backed modes, deterministic post-run checks are terminal when they identify
unsafe evidence. Otherwise the same configured provider performs a structured
post-run assessment using the separate `post_run_v1.txt` prompt. Provider failure or a low-confidence accept/retry escalates
instead of exposing the result.

## Human escalation

An escalated episode terminates automatic execution. The trace and sanitized evidence are
the review packet. Resuming requires a new explicit user-approved call; an escalation is
never silently converted to an allow.

## AgentDojo result normalization

AgentDojo uses a different raw convention for injected episodes: its
injection-task `security` checker returns `true` when the injected attacker
goal was completed. The adapter inverts that value before exposing
TraceGuard's security-success metrics. Clean AgentDojo episodes retain their
native `true` pass value because no injection checker runs.

## Dataset case and predicate semantics

Dataset cases may add source provenance, upstream split, attack family, participant and
payload-family groups, and an authorized benign near-neighbor. Forbidden-call predicates
match the tool name plus arguments using either exact equality or recursive subset
matching. State-diff checks compare declared keys against the disposable service state;
native utility and security checkers remain authoritative whenever an upstream runtime
provides them.

An observation imported from an untrusted dataset or native tool is always represented
as `UNTRUSTED_TOOL` with `may_contain_instructions=true`. Memory and service state are
created per case and discarded after scoring.


## Reviewed email security effects

`security-effects-v1` extracts all `send_email` destination fields, including CC/BCC.
Attachments require an exact trusted constraint or authenticated-source delegation;
a recipient grant never grants access to arbitrary file/calendar attachments. Empty
optional sink lists introduce no effects. The extractor is shared with deterministic
native supervision and is independent of whether the model calls the tool a read/write.


Version 4 adds exact `resource_values` scopes for object selectors and outbound URLs.
A deletion verb or a read classification grants no object or network authority.
`security-effects-v2` requires explicit constraints, delegated fields, or an allowlisted
resource value for supported object IDs, memory paths and URL destinations. Sensitive
account reads require an explicit tool grant. URL grants include the whole URL, including
query parameters. Calendar event identity must come from trusted application resolution;
a retrieved event title alone does not authenticate a target. Historical runs remain v3.


All execution integrations reject an ALLOW that reports high/critical risk, a policy
violation, irrelevance or unnecessary action. Such contradictory decisions escalate;
structured JSON does not make an inconsistent authorization executable. SIMULATED is
handled before tool dispatch and never invokes a real handler or records a real effect.
Contained execution is not a way to override these final checks.


The supported direct filesystem profile uses POSIX descriptor-relative, no-follow reads
and atomic report replacement. Symlinks, hardlinks and special files cannot alias an
approved path to another object; reads are bounded during collection. Unsupported
platform primitives fail closed. This does not authenticate file contents or establish
that an attacker-writable document is true. Container input staging is a separate
integration and still needs its own stronger resource and concurrent-mutation gates.
Runtime configuration and authority are snapshotted; reusable evaluators are copied so
one runtime cannot overwrite another runtime's task authority. One runtime serializes
its check/execute/history operations; no cross-process exactly-once claim is made.
