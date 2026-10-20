"""Durable reservation boundary for explicitly granted typed-tool effects.

The deployment must isolate this process and its downstream credentials from the agent.
This library does not create an OS/process isolation boundary by itself.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from traceguard.control.execution import payment_amount
from traceguard.control.models import ActionRequest, Actor, ExecutionGrant, Role
from traceguard.control.service import AuthorizationError, action_digest
from traceguard.control.signing import canonical, verify
from traceguard.ledger import ExecutionLedger, ExecutionUnknown
from traceguard.supervisor.redaction import redact_value


@dataclass(frozen=True)
class ProviderReceipt:
    action_digest: str
    reference: str
    status: str
    result: str | None = None


class MediatedExecutor:
    def __init__(
        self,
        database: Path,
        *,
        identity: Actor,
        public_key: bytes,
        key_id: str,
        adapter_digest: str,
        execution_domain: str,
        validate_online: Callable[[Actor, ActionRequest, ExecutionGrant], None],
        dispatch: Callable[[ActionRequest], str],
        reconcile_provider: Callable[[dict, str], ProviderReceipt] | None = None,
    ) -> None:
        if Role.EXECUTOR not in identity.roles or Role.AGENT in identity.roles:
            raise ValueError("executor requires a distinct executor identity")
        self.identity = identity.model_copy(deep=True)
        self.public_key, self.key_id = public_key, key_id
        self.adapter_digest = adapter_digest
        self.validate_online, self.dispatch = validate_online, dispatch
        self.reconcile_provider = reconcile_provider
        self.ledger = ExecutionLedger(database, expected_store_id=execution_domain)
        self.database = self.ledger.database

    def reconcile(
        self, operator: Actor, nonce: str, reference: str, *, pending_worker_fenced: bool = False
    ) -> dict:
        """Resolve through a trusted provider lookup, never an agent status claim."""
        record = self.ledger.lookup(nonce)
        if (
            Role.REVIEWER not in operator.roles
            or Role.AGENT in operator.roles
            or record["tenant"] not in operator.tenant_ids
        ):
            raise AuthorizationError("reconciliation requires a separate tenant reviewer")
        if self.reconcile_provider is None:
            raise AuthorizationError("authoritative provider reconciliation is not configured")
        receipt = self.reconcile_provider(dict(record), reference)
        if receipt.action_digest != record["digest"] or receipt.reference != reference:
            raise AuthorizationError("provider receipt does not bind the reserved action")
        result = receipt.result
        if result is not None:
            if len(result.encode()) > 1_048_576:
                raise ValueError("provider receipt exceeds limit")
            try:
                result = json.dumps(redact_value(json.loads(result)), sort_keys=True)
            except json.JSONDecodeError:
                result = redact_value(result)
        return self.ledger.reconcile(
            nonce,
            status=receipt.status,
            result=result,
            actor=operator.subject,
            provider_reference=reference,
            pending_worker_fenced=pending_worker_fenced,
        )

    def execute(self, principal: Actor, action: ActionRequest, grant: ExecutionGrant) -> dict:
        principal, action, grant = (
            principal.model_copy(deep=True),
            action.model_copy(deep=True),
            grant.model_copy(deep=True),
        )
        if (
            Role.AGENT not in principal.roles
            or action.tenant_id not in principal.tenant_ids
            or grant.tenant_id != action.tenant_id
            or grant.task_id != action.task_id
            or (principal.subject, principal.service_key_id)
            != (grant.agent_subject, grant.service_key_id)
            or (
                principal.allowed_operations is not None
                and action.operation not in principal.allowed_operations
            )
            or grant.audience != self.identity.subject
            or grant.key_id != self.key_id
            or grant.adapter_digest != self.adapter_digest
            or grant.execution_domain != self.ledger.store_id
            or grant.expires_at.tzinfo is None
            or grant.expires_at <= datetime.now(UTC)
            or grant.action_digest != action_digest(action)
            or not verify(
                self.public_key,
                grant.model_dump(mode="json", exclude={"signature"}),
                grant.signature,
            )
        ):
            raise AuthorizationError("execution grant does not authorize this caller and action")
        # Fresh authorization is mandatory; there is no offline consequential fallback.
        self.validate_online(self.identity, action, grant)
        amount = payment_amount(action)
        if str(amount) != grant.amount:
            raise AuthorizationError("grant amount mismatches the requested effect")
        scope = (action.tenant_id, principal.subject, principal.service_key_id, action.task_id)
        effect_digest = hashlib.sha256(
            canonical(
                {"tool": action.operation, "arguments": action.arguments, "target": action.target}
            )
        ).hexdigest()
        replay = self.ledger.reserve(
            scope=scope,
            nonce=grant.nonce,
            idempotency_key=action.idempotency_key,
            digest=grant.action_digest,
            effect_digest=effect_digest,
            amount=amount,
            budget_limit=grant.budget_limit,
            repeatable=grant.repeatable,
        )
        if replay is not None:
            return replay
        try:
            self.validate_online(self.identity, action, grant)
        except BaseException:
            self.ledger.finish(grant.nonce, "not_dispatched")
            raise
        try:
            result = self.dispatch(action)
            if not isinstance(result, str) or len(result.encode()) > 1_048_576:
                raise ValueError("executor result must be bounded UTF-8 text")
            # Receipts are sanitized; raw results need a separate release boundary.
            try:
                safe_result = json.dumps(redact_value(json.loads(result)), sort_keys=True)
            except json.JSONDecodeError:
                safe_result = redact_value(result)
        except BaseException as exc:
            self.ledger.finish(grant.nonce, "unknown")
            raise ExecutionUnknown(
                "dispatch outcome is unknown; reconcile with the provider before retry"
            ) from exc
        self.ledger.finish(grant.nonce, "succeeded", safe_result)
        return {
            "nonce": grant.nonce,
            "status": "succeeded",
            "result": safe_result,
            "replayed": False,
        }
