# TraceGuard

TraceGuard is an experimental security framework for governing tool-using AI agents.
Trusted applications define permissions; TraceGuard checks proposed actions, mediates
execution, preserves uncertain outcomes, and controls release of results and artifacts.
There is no supported production release yet. See [security reporting](SECURITY.md)
and [release assurance](docs/release_assurance.md) for scope and remaining release gates.

## Integrate an application

The embedded entry point is `traceguard.security.SecuredTools`. The application owns
its agent loop, tool handlers, approved task, workspace, credentials and classification
labels. Model output and retrieved text cannot grant permissions.

```python
from pathlib import Path

from traceguard.security import SecuredTools
from traceguard.tools.registry import default_registry
from traceguard.types import TaskAuthority, ToolCall

workspace = Path("/application/workspace")
boundary = SecuredTools(
    default_registry(workspace, workspace / "artifacts"),
    TaskAuthority(
        allowed_tools=["read_file"],
        argument_values={"read_file": {"path": "inputs/approved.txt"}},
    ),
    task_id="application-approved-task",
)
result = boundary.execute_call(
    "Read the approved document",
    ToolCall(
        task_id="application-approved-task",
        step_id=0,
        tool_name="read_file",
        arguments={"path": "inputs/approved.txt"},
    ),
    [],
)
# Give the agent only result.observation when it is present.
```

Consequential tools additionally require a provisioned private execution ledger and
its application-configured identity. Provision once through trusted administration;
never recreate missing state during a request or restart. See
[ledger lifecycle](docs/ledger_lifecycle.md) and [execution grants](docs/execution_grants.md).

## Security boundaries

- Explicit tool, argument, object, source and budget grants are compiled with reviewed
  schemas and effect descriptors. Missing, unknown or invalid authority withholds work.
- Optional LLM supervision may block or propose a narrower action; it cannot expand
  deterministic permission. Every rewrite is validated and checked again.
- Durable reservations prevent budget resets and blind retries after uncertain effects.
  Execution and permission to release a result are separate persisted states.
- The embedded profile trusts application code. The isolated report profile separates
  agent, issuer and executor with pinned mTLS identities and constrained credentials.
- Container staging and output collection are bounded. Artifacts remain quarantined
  until an explicit release decision; model inputs and final answers have separate gates.

This is complete mediation only for the configured supported routes. Raw callbacks,
provider credentials and unrestricted network paths must stay outside an adversarial
agent's reach. Read the [security contract](docs/security_framework.md) before deployment.

## Install and verify

Python 3.11+ is required. Docker is required for container validation.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install uv==0.13.1
uv sync --locked --extra dev --no-install-project
uv sync --locked --extra dev --no-build-isolation --no-editable
traceguard smoke
python -m pytest -q
```

See [setup and operations](setup.md) for optional supervisors/Inspect, Docker validation,
package verification and the single-host development deployment profile.

## Documentation

- [Security contract and trust model](docs/security_framework.md)
- [Shared execution contracts](docs/contracts.md)
- [Control-plane API and deployment](docs/control_plane.md)
- [Signed execution grants and reviews](docs/execution_grants.md)
- [Persistent authority and rotation](docs/authority_storage.md)
- [Ledger lifecycle and recovery](docs/ledger_lifecycle.md)
- [Read resource mappings](docs/read_resource_contract.md)
- [Native Inspect integration](docs/inspect_execution.md)
- [Isolated report executor](docs/isolated_executor.md)
- [Artifact and data release](docs/data_release.md)
- [Verification coverage and limitations](docs/verification.md)
- [External security evaluation protocol](docs/security_evaluation.md)
- [Release assurance and outstanding gates](docs/release_assurance.md)
