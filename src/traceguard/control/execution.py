"""Action-bound grant issuance and review continuation for typed tool execution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation

from traceguard.control.models import (
    ActionKind,
    ActionRequest,
    Actor,
    Decision,
    ExecutionGrant,
    Role,
    TaskRegistration,
)
from traceguard.control.service import AuthorizationError, ControlPlane, action_digest
from traceguard.control.signing import Signer, verify
from traceguard.policy.kernel import CompiledAuthority
from traceguard.types import TaskAuthority, ToolCall


def payment_amount(action: ActionRequest) -> Decimal:
    if action.operation not in {"send_money", "schedule_transaction"}:
        return Decimal(0)
    value = action.arguments.get("amount")
    if isinstance(value, bool):
        raise ValueError("invalid payment amount")
    try:
        amount = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("invalid payment amount") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError("invalid payment amount")
    return amount


@dataclass(frozen=True)
class RegisteredTask:
    principal: str
    credential: str
    compiled: CompiledAuthority
    adapter_digest: str


class ExecutionAuthority:
    """Development issuer; a production service requires durable shared registrations."""

    def __init__(self, control: ControlPlane, signing_seed: bytes | None = None) -> None:
        self.control = control
        self._signer = (
            Signer(signing_seed, "traceguard-execution-v1")
            if signing_seed
            else control._execution_signer
        )
        self.key_id = "execution-ed25519-v1"

    @property
    def _tasks(self) -> dict[tuple[str, str], RegisteredTask]:
        return self.control._execution_tasks

    @property
    def _issued(self) -> dict[str, str]:
        return self.control._execution_issued

    @property
    def public_key(self) -> bytes:
        return self._signer.public_key

    def register(self, tenant_id: str, actor: Actor, registration: TaskRegistration) -> str:
        registration = registration.model_copy(deep=True)
        scope = TaskAuthority.model_validate(registration.authority)
        if scope.delegated_fields:
            raise ValueError(
                "execution grants require an authenticated source adapter before delegation"
            )
        compiled = CompiledAuthority.compile(scope, registration.tool_schemas)
        key = (tenant_id, registration.task_id)
        with self.control.transaction():
            self.control._require(actor, Role.ADMIN, tenant_id)
            if key in self._tasks:
                raise ValueError("task registration is immutable; create a newly approved task")
            self._tasks[key] = RegisteredTask(
                registration.agent_subject,
                registration.service_key_id,
                compiled,
                registration.adapter_digest,
            )
            self.control._append_audit(
                tenant_id,
                "task.registered",
                actor.subject,
                {"task_id": registration.task_id, "authority_digest": compiled.digest},
            )
        return compiled.digest

    def _task(self, actor: Actor, action: ActionRequest) -> RegisteredTask:
        self.control._require(actor, Role.AGENT, action.tenant_id)
        if action.kind is not ActionKind.TOOL:
            raise AuthorizationError("execution grants support typed tools only")
        task = self._tasks.get((action.tenant_id, action.task_id))
        if task is None or (actor.subject, actor.service_key_id) != (
            task.principal,
            task.credential,
        ):
            raise AuthorizationError("task is not registered for this principal and credential")
        call = ToolCall(
            task_id=action.task_id,
            step_id=0,
            tool_name=action.operation,
            arguments=action.arguments,
        )
        if task.compiled.evaluate("", call, []).decision.value != "ALLOW":
            raise AuthorizationError("action exceeds the registered strict task grant")
        return task

    def issue(
        self, actor: Actor, action: ActionRequest, audience: str, review_id: str | None = None
    ) -> ExecutionGrant:
        action, actor = action.model_copy(deep=True), actor.model_copy(deep=True)
        with self.control.transaction():
            task = self._task(actor, action)
            decision = self.control.evaluate(actor, action)
            review = None
            if decision.decision is Decision.ESCALATE:
                review = self.control._reviews.get(review_id or "")
                if (
                    review is None
                    or review.review_id != decision.review_id
                    or review.status != "resolved"
                    or review.resolution is None
                    or review.resolution.value != "ALLOW"
                    or review.grant_nonce is not None
                    or review.expires_at <= datetime.now(UTC)
                    or review.action_digest != action_digest(action)
                    or review.policy_epoch != self.control._epochs.get(action.tenant_id)
                    or (review.agent_subject, review.service_key_id, review.task_id)
                    != (actor.subject, actor.service_key_id, action.task_id)
                ):
                    raise AuthorizationError("action requires a current action-bound review")
            elif decision.decision is not Decision.ALLOW:
                raise AuthorizationError("policy does not authorize grant issuance")
            scope = TaskAuthority.model_validate_json(task.compiled.scope_json)
            policy = self.control.active_policy(action.tenant_id)
            if policy is None:
                raise AuthorizationError("active policy is unavailable")
            grant = ExecutionGrant(
                tenant_id=action.tenant_id,
                task_id=action.task_id,
                agent_subject=actor.subject,
                service_key_id=actor.service_key_id or "",
                audience=audience,
                action_digest=action_digest(action),
                authority_digest=task.compiled.digest,
                adapter_digest=task.adapter_digest,
                policy_id=policy.policy_id,
                policy_epoch=self.control._epochs[action.tenant_id],
                expires_at=datetime.now(UTC) + timedelta(seconds=60),
                repeatable=action.operation in scope.repeatable_tools,
                amount=str(payment_amount(action)),
                budget_limit=str(scope.max_amount) if scope.max_amount is not None else None,
                key_id=self.key_id,
                signature="",
            )
            grant.signature = self._signer.sign(
                grant.model_dump(mode="json", exclude={"signature"})
            )
            self._issued[grant.nonce] = grant.model_dump_json()
            if review is not None:
                review.grant_nonce = grant.nonce
            self.control._append_audit(
                action.tenant_id,
                "execution.granted",
                actor.subject,
                {
                    "nonce": grant.nonce,
                    "action_digest": grant.action_digest,
                    "review_id": review_id,
                },
            )
            return grant

    def validate(self, executor: Actor, action: ActionRequest, grant: ExecutionGrant) -> None:
        with self.control.transaction():
            self.control._require(executor, Role.EXECUTOR, action.tenant_id)
            if Role.AGENT in executor.roles or not executor.service_key_id:
                raise AuthorizationError("executor requires a distinct service identity")
            unsigned = grant.model_dump(mode="json", exclude={"signature"})
            if (
                grant.audience != executor.subject
                or grant.key_id != self.key_id
                or self._issued.get(grant.nonce) != grant.model_dump_json()
                or not verify(self.public_key, unsigned, grant.signature)
                or grant.expires_at <= datetime.now(UTC)
                or grant.action_digest != action_digest(action)
                or grant.policy_epoch != self.control._epochs.get(action.tenant_id)
            ):
                raise AuthorizationError("execution grant is invalid, expired or revoked")
            principal = Actor(
                subject=grant.agent_subject,
                roles={Role.AGENT},
                service_key_id=grant.service_key_id,
                tenant_ids={grant.tenant_id},
            )
            task = self._task(principal, action)
            if task.compiled.digest != grant.authority_digest:
                raise AuthorizationError("task authority changed")
