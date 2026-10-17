# Security completion follow-up

This series follows the current-main reassessment at `4569d0a`. Each change must have
secure-outcome regressions; passing tests do not replace independent security review.

| Workstream | Implemented contract | Validation |
| --- | --- | --- |
| Staging and strict enforcement | Descriptor-relative no-follow regular-file copies; hardlink/special-file rejection; shared entry/byte/depth/time budgets; strict grants cannot be skipped by an LLM ablation switch | 118 focused staging, sandbox, strict-mode and supervisor tests passed |

Sandbox `input_limits` apply while traversing and copying, before Docker starts. The
workspace and staging parent are application-owned. Concurrently changed objects are
rejected; a source name replaced after open cannot redirect the open descriptor.

Selecting strict scope runs explicit authorization even in an LLM-only research arm.
For a genuinely unguarded ablation select research scope explicitly. `mode="none"`
with strict scope is rejected. This changes strict ablation semantics intentionally.

Still to deliver: durable embedded effects and reconciliation; an isolated authenticated
executor integration; durable issuer state and resource budgets; sandbox/quarantine/data
release controls; corrected effect metrics and reproducible evaluation; release security
evidence and support policy. External reviewers and application pilots are not arranged.
The repository owner's distribution license decision remains pending.
