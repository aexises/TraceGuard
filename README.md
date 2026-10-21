# TraceGuard

**Control which actions an AI agent can execute and which results it can release.**

TraceGuard is a security framework for applications that let AI agents use tools.
Your application defines the approved task and permissions. TraceGuard checks each
proposed action against that authority, mediates supported tool execution, records
side effects durably, and applies separate controls to data leaving the boundary.

Use it to scope document access, constrain generated reports, enforce action budgets,
and stop uncertain operations from being repeated after a timeout or restart.
Your application keeps its planner, models and conversation loop.

**Status:** experimental. There is no supported production release or selected
distribution license yet. Independent review, external evaluation and real application
pilots remain [release requirements](docs/release_assurance.md).

## How it works

1. **Approve a task.** Trusted application code supplies identity, allowed tools,
   arguments, resources and budgets. Prompts and retrieved content cannot grant access.
2. **Check the effective action.** TraceGuard validates the tool schema, normalizes
   reviewed defaults and checks deterministic authority. An optional LLM supervisor
   can withhold an action or propose a rewrite; every rewrite passes the checks again.
3. **Execute through the boundary.** Supported handlers run only after authorization.
   Consequential actions reserve their identity and budget in a private durable ledger.
4. **Account for the outcome.** Replays use accepted receipts. A possibly completed
   effect holds the task for reconciliation instead of being blindly retried.
5. **Authorize release.** Execution permission is separate from permission to publish
   an artifact, send data to a model provider or return a final answer.

## Choose an integration

| Route | Use it for | Boundary you must supply |
| --- | --- | --- |
| [Embedded `SecuredTools`](docs/integration.md) | Add strict tool enforcement to an application-owned agent loop | Trusted application and handlers; protect credentials and prevent raw dispatch |
| [Native Inspect integration](docs/inspect_execution.md) | Govern reviewed reads and explicitly wrapped native tool calls | A trusted solver that exposes only guarded callbacks |
| [Isolated report executor](docs/isolated_executor.md) | Separate an untrusted agent from report-writing authority | Workload identities, private state and a validated container/network deployment |
| [Control-plane API](docs/control_plane.md) | Centralize tenant policy, reviews and signed execution grants | An authenticated application factory and an appropriate state backend |

The isolated executor currently exposes a narrow public text/JSON report operation.
The bundled HTTP service and Kubernetes template are development profiles. A generic
provider proxy, arbitrary shell execution and unrestricted connectors are not supplied.
See the [security model](docs/security_framework.md) for the trust assumptions of each route.

## Try it locally

From a checkout, use Python 3.11+ and the committed dependency lock:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install uv==0.13.1
uv sync --locked --extra dev --no-install-project
uv sync --locked --extra dev --no-build-isolation --no-editable
traceguard smoke
```

The smoke command runs an explicitly authorized calculation offline. It needs no model
credentials or Docker. See [setup](setup.md) for optional integrations and container checks.

This complete example permits one document and withholds a different path:

```python
from pathlib import Path
from tempfile import TemporaryDirectory

from traceguard.security import SecuredTools
from traceguard.tools.registry import default_registry
from traceguard.types import TaskAuthority, ToolCall

with TemporaryDirectory() as temporary:
    workspace = Path(temporary)
    (workspace / "inputs").mkdir()
    (workspace / "inputs/approved.txt").write_text("Approved document", encoding="utf-8")
    (workspace / "inputs/private.txt").write_text("Private document", encoding="utf-8")
    boundary = SecuredTools(
        default_registry(workspace, workspace / "artifacts"),
        TaskAuthority(
            allowed_tools=["read_file"],
            argument_values={"read_file": {"path": "inputs/approved.txt"}},
        ),
        task_id="read-approved-document",
    )
    for step, path in enumerate(("inputs/approved.txt", "inputs/private.txt")):
        result = boundary.execute_call(
            "Read the approved document",
            ToolCall(
                task_id="read-approved-document",
                step_id=step,
                tool_name="read_file",
                arguments={"path": path},
            ),
            [],
        )
        if result.observation is not None:
            print(result.observation.content)
        else:
            print(f"Withheld: {path}")
```

Only accepted observations go back to the agent. Application-owned classification and
sink permissions still determine whether those data may leave the application.
Consequential tools also need a provisioned ledger; follow the
[integration guide](docs/integration.md) before adding writes or external effects.

## Security scope

TraceGuard enforces configured authority on supported execution routes. Unknown effects,
unreviewed read mappings, invalid schemas and missing authority withhold work. Strict
deterministic enforcement is mandatory on the public embedded route.

The application must prevent bypass through raw handlers, provider credentials,
unrestricted network access or writable state. Embedded Python does not isolate arbitrary
hostile code. Data release uses trusted classifications and bounded checks; it is not
general semantic secret detection. Passing tests does not establish universal prompt
injection resistance or independent certification.

## Documentation

Start with the [documentation map](docs/index.md), then choose:

- **Build:** [setup](setup.md), [application integration](docs/integration.md),
  [contracts](docs/contracts.md), [read resource mappings](docs/read_resource_contract.md).
- **Operate:** [signed grants and reviews](docs/execution_grants.md),
  [authority storage](docs/authority_storage.md), [ledger recovery](docs/ledger_lifecycle.md),
  [data release](docs/data_release.md).
- **Assess:** [security model](docs/security_framework.md),
  [verification coverage](docs/verification.md), [external evaluation](docs/security_evaluation.md),
  [release assurance](docs/release_assurance.md), [vulnerability reporting](SECURITY.md).
