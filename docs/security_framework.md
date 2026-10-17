TraceGuard security framework contract and reference comparison
==============================================================

This document describes the security implementation series based on the 17 October 2026
audit. It does not certify the project for production or replace the baseline audit.

**Is the deterministic policy a dummy?** No: the original implementation has real schema,
path, repeat, exact-argument, budget and terminal-denial checks. However, its English verb,
destination and task-relevance grammar is a research heuristic. It is not an adequate
authorization root. The strict product entry point is `traceguard.security.SecuredTools`.
It compiles explicit application grants and never infers new permission from English.

`TaskAuthority.enforcement_mode="research"` remains the compatibility default for the
existing research/ablation interfaces. Do not advertise that API choice as strict mode.
`SecuredTools` selects strict mode, requires an explicit tool allowlist and snapshots its
compiled grant and schemas. Native and dataset integrations select the same kernel when
their trusted application scope explicitly selects strict mode.

**Strict semantics**

- All mutating/command arguments require an exact constraint, resource allowlist,
  authenticated-source delegation or reviewed generated-field permission. An unfamiliar
  optional field is not implicitly granted. Only reviewed empty email optionals have
  no-effect semantics; null/empty updates can otherwise be consequential.
- Generated text may be permitted for specific content fields. It cannot mint recipients,
  object IDs, command arguments or budgets. This is a permission to generate content,
  not proof of factual correctness or arbitrary-secret confidentiality.
- Object selectors and outbound URLs require explicit resource scope even on read tools.
  Exact JSON equality does not coerce booleans, numbers and strings into one identity.
- Schemas, immutable grant snapshots and versioned effect descriptors participate in the
  grant digest. Unknown schemas/effects, invalid grants and missing authority withhold.
- Model decisions may withhold more work but cannot expand the grant. Contradictory
  ALLOW decisions do not reach execution. Rewrites pass the same checks again.
- Control-plane and offline policy matching share deny precedence and structural HTTP
  matching. Unmatched actions cannot receive default ALLOW; client evidence is untrusted.

The custom runtime additionally enforces its filesystem and containment restrictions.
Strict grant validity alone does not assert that an arbitrary integration's handler is
correct. The application process/tool adapters remain trusted in the embedded profile.
The stronger isolated-executor profile must additionally remove direct credentials and
unrestricted egress from the agent process.

**Measured development comparison**

Run after installation:

```bash
python -m benchmarks.policy_conformance
```

For source-checkout verification before reinstalling, use
`PYTHONPATH=src .venv/bin/python -m benchmarks.policy_conformance`.

The comparison contains ten authored development cases covering required calendar fields,
ungranted location/description additions, empty updates, title substitution and authorized
utility under two goal phrasings. With the same declared task constraints, the current
research grammar makes 4/10 expected decisions and strict grants make 10/10. These cases
were authored during implementation and are regression evidence. They are not held-out
data, independent attack families, live-agent task success, or an upstream benchmark.
The conformance tests also check agreement across the strict kernel, native deterministic
supervisor and dataset gateway, plus actual authorized report execution in SecuredTools.

**External references and what must be exceeded**

| Reference | Required architectural baseline | TraceGuard evidence and remaining gap |
| --- | --- | --- |
| [OWASP Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | Minimal tools/privilege, user scope, downstream complete mediation | Explicit grants, complete email sink checks and execution invariants have executable regressions. Removing all agent bypass credentials/egress still requires a deployment integration and independent validation. |
| [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Structural destination validation, controlled resolution and redirects | Public HTTPS transport validates every DNS answer, pins an approved IP, authenticates the hostname and rejects redirects. Tests use fake DNS/transport; live integration, proxy/network perimeter and target-specific behavior need validation. |
| [NIST agent identity foundations](https://www.nist.gov/blogs/cybersecurity-insights/back-future-why-agentic-ai-needs-strong-identity-foundation) | Scoped identity, delegation and credential lifecycle | Tenant/operation scopes and action-bound receipt tests exist. Real identity validation, workload identity, provider credentials, rotation and revocation are still deployment requirements. |
| [CaMeL](https://arxiv.org/abs/2503.18813), [official code](https://github.com/google-research/camel-prompt-injection) | Capabilities plus separation of control/data flow | TraceGuard's explicit grants improve its own authorization boundary. It has not implemented CaMeL's interpreter/information-flow guarantees, reproduced its evaluation or shown superior utility/security. Literal occurrence provenance must not be presented as causal taint tracking. |
| [Progent](https://arxiv.org/abs/2504.11703), [author repository](https://github.com/sunblaze-ucb/progent) | Programmable fine-grained privilege control | Strict grants/schema checks overlap with this baseline. Incremental semantic value and practical security/utility benefits require a matched comparison, not a claim based on architectural naming. |

OWASP/NIST are requirements to meet and make independently testable, not numeric
competitors. To claim improvement over CaMeL or Progent, pre-register a compatible
AgentDojo revision, task/attack split, model/provider settings, privilege budget, recovery
rules, prompt versions and resource/cost accounting. Run both implementations under
matched conditions; report secure task completion, actual effects/data releases, benign
withholds, escalation/review cost and paired task-clustered uncertainty. Freeze the protocol
before final runs and include fixed-budget adaptive attacks. No such superiority claim
is supported by the development conformance comparison.

**Release gates still open after the initial PR series**

Independent security review; genuine authentication/source identity; deployment-enforced
credential/egress isolation; durable transactional execution/recovery; bounded sandbox
disk/inodes and staged inputs; artifact quarantine/release; final-answer/model-provider
data release; wider held-out/adaptive evaluation; native benchmark reproduction; supported
deployment conformance; advisory/secret scanning, signed releases and vulnerability support.
Do not equate completing the first ten implementation PRs with completing these gates.
