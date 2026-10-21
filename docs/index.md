# TraceGuard documentation

TraceGuard governs application-owned agent actions: approval, deterministic checks,
execution accounting and data release. Start with the [product overview](../README.md)
and [setup guide](../setup.md), then follow the path for your deployment.

## Build an integration

| Guide | Use it to |
| --- | --- |
| [Application integration](integration.md) | Add the embedded boundary and handle allowed, withheld and uncertain outcomes |
| [Contracts](contracts.md) | Understand typed calls, authority, decisions and trace semantics |
| [Read resource mappings](read_resource_contract.md) | Approve actual read targets and reviewed defaults |
| [Inspect integration](inspect_execution.md) | Wrap native tool execution without exposing raw callbacks |
| [Control plane](control_plane.md) | Integrate tenant policy, authenticated roles and HTTP decision APIs |
| [Execution grants](execution_grants.md) | Connect immutable tasks, human reviews and credential-holding executors |
| [Isolated reports](isolated_executor.md) | Evaluate the separate agent/issuer/executor deployment |

## Operate the boundary

| Guide | Use it to |
| --- | --- |
| [Authority storage](authority_storage.md) | Provision, back up and rotate single-host issuer state |
| [Execution ledger](ledger_lifecycle.md) | Preserve reservations and recover uncertain effects safely |
| [Data release](data_release.md) | Quarantine artifacts and authorize model, artifact and final-answer sinks |

## Assess a candidate

| Guide | Use it to |
| --- | --- |
| [Security model](security_framework.md) | Identify trust roots, supported profiles and limits |
| [Verification](verification.md) | Map contracts to regression tests and operational checks |
| [External evaluation](security_evaluation.md) | Freeze comparisons and analyze effect-grounded outcomes |
| [Release assurance](release_assurance.md) | Prepare source-bound evidence and understand blocked promotion gates |
| [Security reporting](../SECURITY.md) | Report a vulnerability privately |

The project is experimental. These guides describe implemented contracts and bounded
validation; they do not replace independent review or validate an untested deployment.
