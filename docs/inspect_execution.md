# Inspect supported execution routes

`traceguard_inspect_approver` is a pre-tool policy callback. In strict mode it rejects
all consequential/unknown tools even when gateway evaluation permits the proposal.
An approval callback cannot determine whether an operation actually ran, and native
history text is not definitive provider accounting. Do not configure approval alone as
the security boundary for side effects. Research ablations retain their labelled behavior.

Use `GuardedInspectExecutor` from `benchmarks.datasets.inspect_executor` in a trusted
solver/application loop for native string-result tool effects. Construct a strict
`SupervisionGateway` with schemas from the actual `ToolDef.parameters` using
`model_dump(mode="json", exclude_none=True)`, the approved task scope, a provisioned
ledger path/expected identity, native tool instances and a fixed application `task_id`.
The constructor verifies each native handler's schema matches the approved schema.
Read schemas additionally require the inspected mapping described in `read_resource_contract.md`.

For each native `ToolCall`, await `executor.execute(call, user_goal=trusted_goal,
history=native_messages)` and append `result.message` (a real `ChatMessageTool`) to the
native conversation. Only this route may dispatch its credential-holding native tools;
do not simultaneously expose raw callbacks through an ordinary Inspect tool loop.
The adapter is explicit solver integration, not an automatic patch of every Inspect
execution API. Host application and handler credentials remain trusted; isolation is
required separately for an adversarial agent process.

Native call IDs bind to task/domain and immutable effective arguments. The wrapper
checks current strict authority, evaluates new proposals, reserves before invoking the
actual native callback, and commits bounded sanitized results after success. Repeated
IDs return accepted receipts; changed arguments with the same ID are denied. A validated
rewrite must be resubmitted with a new native ID; it cannot dispatch under its original
identity. Default normalization is performed before comparison. Policy-version changes
invalidate stored result acceptance using the ledger's disposition contract.

The ledger accounts for budgets and holds across concurrent wrappers and restarts;
observations/history are provenance context. Tool-returned success/failure text cannot
reset accounting. Exceptions, cancellation and missing/unsupported results after invocation
retain unknown reservations. Pending/unknown results require the same trusted provider
reconciliation and worker fencing described in `ledger_lifecycle.md`; this adapter does
not invent provider receipts or automatically clear holds. Real payment/provider/currency
semantics remain unsupported beyond disposable conformance fixtures.

Validation uses actual Inspect ToolCalls, ToolDefs, decorated native tools, approvals,
ChatMessageTool histories and the real gateway. Harmless fixture transfers demonstrate
60+40 under budget 100, reject 60+61 and competing pending effects, correlate stable native
IDs, and preserve holds after post-effect failure, missing result and cancellation.
