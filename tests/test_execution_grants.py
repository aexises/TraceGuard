import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from traceguard.control.execution import ExecutionAuthority
from traceguard.control.models import (
    ActionRequest,
    Actor,
    Decision,
    PolicyDraft,
    PolicyRule,
    ReviewResolution,
    Role,
    RuleMatch,
    TaskRegistration,
)
from traceguard.control.service import AuthorizationError, ControlPlane
from traceguard.executor import ExecutionUnknown, MediatedExecutor
from traceguard.ledger import ExecutionLedger
from traceguard.types import TaskAuthority


def actor(name, role, key=None):
    return Actor(subject=name, roles={role}, service_key_id=key, tenant_ids={"tenant"})


def configured(
    tmp_path, *, review=False, tool="send_email", budget=None, dispatch=None, control=None
):
    control = control or ControlPlane(b"test-only-signing-seed-" + b"x" * 32)
    author, approver = actor("author", Role.ADMIN), actor("approver", Role.APPROVER)
    policy = control.create_draft(
        "tenant",
        author,
        PolicyDraft(
            name="tools",
            rules=[
                PolicyRule(
                    name="tools",
                    priority=1,
                    match=RuleMatch(kind="tool", operation=tool),
                    decision=Decision.ESCALATE if review else Decision.ALLOW,
                    reason="review" if review else "grant",
                )
            ],
        ),
    )
    control.submit_policy("tenant", author, policy.policy_id)
    control.approve_policy("tenant", approver, policy.policy_id)
    agent, executor_identity = (
        actor("agent", Role.AGENT, "agent-key"),
        actor("executor", Role.EXECUTOR, "executor-key"),
    )
    issuer = ExecutionAuthority(control)
    execution_domain = ExecutionLedger.provision(tmp_path / "ledger.sqlite")
    if tool == "send_money":
        fields = {"recipient": {"type": "string"}, "amount": {"type": "number"}}
        scope = TaskAuthority(
            enforcement_mode="strict",
            allowed_tools=[tool],
            argument_values={tool: {"recipient": "account-1"}},
            max_amount=budget,
        )
        arguments = {"recipient": "account-1", "amount": 60}
    else:
        fields = {"to": {"type": "string"}, "body": {"type": "string"}}
        scope = TaskAuthority(
            enforcement_mode="strict",
            allowed_tools=[tool],
            argument_values={tool: {"to": "alice@example.test"}},
            generated_fields={tool: ["body"]},
        )
        arguments = {"to": "alice@example.test", "body": "Approved text"}
    issuer.register(
        "tenant",
        author,
        TaskRegistration(
            task_id="task",
            agent_subject="agent",
            service_key_id="agent-key",
            execution_domain=execution_domain,
            authority=scope.model_dump(mode="json"),
            adapter_digest="a" * 64,
            tool_schemas={
                tool: {
                    "type": "object",
                    "properties": fields,
                    "required": list(fields),
                    "additionalProperties": False,
                }
            },
        ),
    )
    effects = []

    def handler(action):
        effects.append(dict(action.arguments))
        return '{"status":"done","password":"FAKE_CANARY"}'

    def make_executor():
        return MediatedExecutor(
            tmp_path / "ledger.sqlite",
            identity=executor_identity,
            public_key=issuer.public_key,
            key_id=issuer.key_id,
            adapter_digest="a" * 64,
            validate_online=issuer.validate,
            execution_domain=execution_domain,
            dispatch=dispatch or handler,
        )

    action = ActionRequest(
        tenant_id="tenant",
        task_id="task",
        idempotency_key="effect-key",
        kind="tool",
        operation=tool,
        arguments=arguments,
    )
    return control, issuer, agent, make_executor, action, effects


def test_grant_dispatch_is_exact_single_use_and_durable_across_executor_restart(tmp_path):
    control, issuer, agent, factory, action, effects = configured(tmp_path)
    grant = issuer.issue(agent, action, "executor")
    first = factory().execute(agent, action, grant)
    assert len(effects) == 1 and first["status"] == "succeeded"
    assert "FAKE_CANARY" not in first["result"]
    assert factory().execute(agent, action, grant)["replayed"]
    assert len(effects) == 1
    changed = action.model_copy(deep=True)
    changed.arguments["body"] = "changed after approval"
    with pytest.raises(AuthorizationError):
        factory().execute(agent, changed, grant)
    assert len(effects) == 1


def test_wrong_principal_audience_and_signature_do_not_dispatch(tmp_path):
    _, issuer, agent, factory, action, effects = configured(tmp_path)
    grant = issuer.issue(agent, action, "executor")
    with pytest.raises(AuthorizationError):
        factory().execute(actor("other", Role.AGENT, "other"), action, grant)
    with pytest.raises(AuthorizationError):
        factory().execute(agent, action, grant.model_copy(update={"audience": "other"}))
    with pytest.raises(AuthorizationError):
        factory().execute(agent, action, grant.model_copy(update={"signature": "tampered"}))
    assert effects == []


def test_review_approval_is_bound_to_action_epoch_and_one_grant(tmp_path):
    control, issuer, agent, factory, action, effects = configured(tmp_path, review=True)
    decision = control.evaluate(agent, action)
    with pytest.raises(AuthorizationError):
        issuer.issue(agent, action, "executor")
    control.resolve_review(
        "tenant",
        actor("reviewer", Role.REVIEWER),
        decision.review_id,
        ReviewResolution.ALLOW,
        "approved exact preview",
    )
    grant = issuer.issue(agent, action, "executor", decision.review_id)
    with pytest.raises(AuthorizationError):
        issuer.issue(agent, action, "executor", decision.review_id)
    assert factory().execute(agent, action, grant)["status"] == "succeeded"
    assert len(effects) == 1


def test_new_policy_revokes_issued_grant_before_dispatch(tmp_path):
    control, issuer, agent, factory, action, effects = configured(tmp_path)
    grant = issuer.issue(agent, action, "executor")
    author = actor("author", Role.ADMIN)
    deny = control.create_draft(
        "tenant",
        author,
        PolicyDraft(
            name="revoked",
            rules=[
                PolicyRule(
                    name="deny",
                    priority=1,
                    match=RuleMatch(),
                    decision=Decision.BLOCK,
                    reason="revoked",
                )
            ],
        ),
    )
    control.submit_policy("tenant", author, deny.policy_id)
    control.approve_policy("tenant", actor("approver", Role.APPROVER), deny.policy_id)
    with pytest.raises(AuthorizationError):
        factory().execute(agent, action, grant)
    assert effects == []


def test_dispatch_failure_is_unknown_and_is_never_blindly_retried(tmp_path):
    effects = []

    def uncertain(action):
        effects.append(action.operation)
        raise TimeoutError("provider may already have executed")

    _, issuer, agent, factory, action, _ = configured(tmp_path, dispatch=uncertain)
    grant = issuer.issue(agent, action, "executor")
    with pytest.raises(ExecutionUnknown):
        factory().execute(agent, action, grant)
    with pytest.raises(ExecutionUnknown):
        factory().execute(agent, action, grant)
    assert effects == ["send_email"]


def test_parallel_distinct_payments_cannot_exceed_task_budget(tmp_path):
    _, issuer, agent, factory, action, effects = configured(tmp_path, tool="send_money", budget=100)
    other = action.model_copy(deep=True, update={"idempotency_key": "other-key"})
    other.arguments["amount"] = 61
    grants = [issuer.issue(agent, request, "executor") for request in [action, other]]
    executor = factory()
    start = threading.Barrier(2)

    def execute(pair):
        start.wait()
        try:
            return executor.execute(agent, *pair)["status"]
        except (AuthorizationError, ExecutionUnknown):
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(execute, zip([action, other], grants, strict=True)))
    assert sorted(outcomes) == ["denied", "succeeded"]
    assert len(effects) == 1


def test_online_validation_outage_prevents_any_dispatch(tmp_path):
    _, issuer, agent, factory, action, effects = configured(tmp_path)
    grant = issuer.issue(agent, action, "executor")
    executor = factory()

    def offline(*_):
        raise ConnectionError("authority unavailable")

    executor.validate_online = offline
    with pytest.raises(ConnectionError):
        executor.execute(agent, action, grant)
    assert effects == []


def test_adapter_version_mismatch_and_expired_grants_do_not_dispatch(tmp_path):
    from datetime import UTC, datetime, timedelta

    _, issuer, agent, factory, action, effects = configured(tmp_path)
    grant = issuer.issue(agent, action, "executor")
    executor = factory()
    executor.adapter_digest = "b" * 64
    with pytest.raises(AuthorizationError):
        executor.execute(agent, action, grant)
    executor.adapter_digest = "a" * 64
    expired = grant.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    with pytest.raises(AuthorizationError):
        executor.execute(agent, action, expired)
    assert effects == []


def test_approval_cannot_cross_task_or_override_terminal_policy_deny(tmp_path):
    control, issuer, agent, factory, action, effects = configured(tmp_path, review=True)
    decision = control.evaluate(agent, action)
    control.resolve_review(
        "tenant",
        actor("reviewer", Role.REVIEWER),
        decision.review_id,
        ReviewResolution.ALLOW,
        "approved",
    )
    changed = action.model_copy(update={"task_id": "other", "idempotency_key": "new-other-key"})
    with pytest.raises(AuthorizationError):
        issuer.issue(agent, changed, "executor", decision.review_id)
    author = actor("author", Role.ADMIN)
    deny = control.create_draft(
        "tenant",
        author,
        PolicyDraft(
            name="deny",
            rules=[
                PolicyRule(
                    name="deny",
                    priority=0,
                    match=RuleMatch(),
                    decision=Decision.BLOCK,
                    reason="deny",
                )
            ],
        ),
    )
    control.submit_policy("tenant", author, deny.policy_id)
    control.approve_policy("tenant", actor("approver", Role.APPROVER), deny.policy_id)
    with pytest.raises((AuthorizationError, ValueError)):
        issuer.issue(agent, action, "executor", decision.review_id)
    assert effects == []


def test_unknown_effect_requires_provider_receipt_and_separate_reviewer(tmp_path):
    from traceguard.executor import ProviderReceipt

    def uncertain(_):
        raise TimeoutError("effect unknown")

    _, issuer, agent, factory, action, _ = configured(tmp_path, dispatch=uncertain)
    executor = factory()
    grant = issuer.issue(agent, action, "executor")
    with pytest.raises(ExecutionUnknown):
        executor.execute(agent, action, grant)
    reviewer = actor("operator", Role.REVIEWER)
    with pytest.raises(AuthorizationError):
        executor.reconcile(reviewer, grant.nonce, "provider-receipt-1")
    executor.reconcile_provider = lambda row, reference: ProviderReceipt(
        row["digest"], reference, "succeeded", '{"status":"done","password":"FAKE_CANARY"}'
    )
    with pytest.raises(AuthorizationError):
        executor.reconcile(agent, grant.nonce, "provider-receipt-1")
    resolved = executor.reconcile(reviewer, grant.nonce, "provider-receipt-1")
    assert resolved["status"] == "succeeded"
    assert "FAKE_CANARY" not in resolved["result"]
    assert executor.execute(agent, action, grant)["replayed"]
    with pytest.raises(ValueError):
        executor.reconcile(reviewer, grant.nonce, "provider-receipt-2")
