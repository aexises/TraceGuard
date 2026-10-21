# Integrate application-owned tools

Use `traceguard.security.SecuredTools` when your application owns the planner and tool
handlers. It provides strict action enforcement in the application process. Start with
the complete read-only example in the [README](../README.md#try-it-locally).

## Define authority in trusted application code

Create one boundary for an approved task. Supply its fixed `task_id`, registry and
`TaskAuthority` from authenticated application policy, not from model output or retrieved
instructions. `SecuredTools` forces strict mode, requires an explicit allowlist and
compiles authority against the registry's schemas and effect descriptors.

| Permission | Purpose |
| --- | --- |
| `allowed_tools` | Name the tools the task may propose |
| `argument_values` | Bind fields to exact approved JSON values |
| `resource_values` | Allow reviewed resource sets, including read selectors |
| `generated_fields` | Allow model-generated content in reviewed fields, not arbitrary recipients, commands or amounts |
| `delegated_fields` | Delegate fields only from authenticated sources supported by the integration |
| `max_amount` | Bound cumulative amounts for supported declared effects |
| `repeatable_tools` | Explicitly permit repetition where supported; uncertainty still holds the task |

Allowlisting a name alone does not authorize its consequential fields. Read tools need
a [reviewed resource mapping](read_resource_contract.md). A new custom handler needs
reviewed schema, effects, resource/default semantics and regression coverage; borrowing a
familiar tool name does not establish its safety.

## Add a consequential action

The following disposable example writes one approved report path. In a real deployment,
perform provisioning once as administration, then store `ledger_id` in protected
configuration and reopen the same ledger on every restart.

```python
from pathlib import Path
from tempfile import TemporaryDirectory

from traceguard.ledger import ExecutionLedger
from traceguard.security import SecuredTools
from traceguard.tools.registry import default_registry
from traceguard.types import TaskAuthority, ToolCall

with TemporaryDirectory() as temporary:
    workspace = Path(temporary)
    ledger_path = workspace / "state" / "effects.db"
    ledger_id = ExecutionLedger.provision(ledger_path)  # One-time administration.

    def open_boundary():
        return SecuredTools(
            default_registry(workspace, workspace / "artifacts"),
            TaskAuthority(
                allowed_tools=["write_report"],
                argument_values={"write_report": {"path": "artifacts/report.txt"}},
                generated_fields={"write_report": ["content"]},
            ),
            task_id="approved-report",
            ledger_path=ledger_path,
            ledger_id=ledger_id,
        )

    call = ToolCall(
        task_id="approved-report",
        step_id=0,
        call_id="report-operation-1",
        tool_name="write_report",
        arguments={"path": "artifacts/report.txt", "content": "Public report draft"},
    )
    first = open_boundary().execute_call("Write the approved report", call, [])
    replay = open_boundary().execute_call("Write the approved report", call, [])
    assert first.trace.episode_outcome == "EXECUTED"
    assert replay.trace.episode_outcome == "REPLAYED"
    print(first.trace.episode_outcome, replay.trace.episode_outcome)
```

The second boundary simulates reopening the same task after restart and reuses its
accepted receipt without another write. The example writes inside a private temporary
workspace; it does not authorize public artifact publication. A direct filesystem write and a quarantined container artifact are different
paths; use the [data-release contract](data_release.md) when exposing files to consumers.
Never serve the application workspace as an unrestricted public directory.

## Handle outcomes explicitly

Pass proposed `ToolCall` objects and relevant observations to `execute_call`. Keep stable
operation IDs across retries; do not mint a new ID to bypass a rejection or unknown result.
Return only a present `result.observation` to the agent, subject to your sink policy.

| Outcome | Application response |
| --- | --- |
| `EXECUTED` / `REPLAYED` | Consume only the accepted observation; record the trace |
| `BLOCK` | Do not dispatch the original handler or expose withheld data |
| `ESCALATE` | Stop that task context and route to authorized review/recovery |
| `EXECUTION_UNKNOWN` | Stop new effects, preserve state and reconcile actual provider evidence |
| Result withheld after dispatch | Treat execution and disclosure separately; do not rerun the effect to obtain output |

This table describes common outcomes, not an exhaustive trace enum. Consult
[contracts](contracts.md) for dispatch/result distinctions and
[ledger recovery](ledger_lifecycle.md) before implementing retries.

## Add optional supervision and release controls

Pass a configured `Supervisor` if the application needs semantic review. Deterministic
authority remains mandatory. Provider failures withhold work; every proposed rewrite
is checked again. For known supervisor providers, `SecuredTools` applies `GuardedProvider`
to the serialized request. External data release defaults to denied.

Supply a trusted `release_gate` and `model_input_label` before allowing model inputs.
Use `release_answer` for the separate final-answer sink. Labels must come from trusted
application/source classification, not a model's claim that its output is public.
Enable `post_run_reevaluation=True` when container results require supervisor review;
set and maintain a trusted `result_policy_version`. See [data release](data_release.md).

## Choose process separation when needed

Embedded enforcement trusts your application, registry and host. Remove raw callbacks,
credentials and unguarded network paths from the agent's reach. If the agent runs
arbitrary code or must not share executor secrets, use a separately isolated executor.
The current [isolated profile](isolated_executor.md) supports public text/JSON reports;
it does not turn arbitrary providers into supported connectors.
