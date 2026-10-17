"""Durable reservation boundary for explicitly granted typed-tool effects.

The deployment must isolate this process and its downstream credentials from the agent.
This library does not create an OS/process isolation boundary by itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from traceguard.control.execution import payment_amount
from traceguard.control.models import ActionRequest, Actor, ExecutionGrant, Role
from traceguard.control.service import AuthorizationError, action_digest
from traceguard.control.signing import canonical, verify
from traceguard.supervisor.redaction import redact_value


class ExecutionUnknown(RuntimeError):
    """An effect may have happened; retry requires authoritative provider reconciliation."""


class MediatedExecutor:
    def __init__(
        self,
        database: Path,
        *,
        identity: Actor,
        public_key: bytes,
        key_id: str,
        adapter_digest: str,
        validate_online: Callable[[Actor, ActionRequest, ExecutionGrant], None],
        dispatch: Callable[[ActionRequest], str],
    ) -> None:
        if Role.EXECUTOR not in identity.roles or Role.AGENT in identity.roles:
            raise ValueError("executor requires a distinct executor identity")
        self.identity = identity.model_copy(deep=True)
        self.public_key, self.key_id = public_key, key_id
        self.adapter_digest = adapter_digest
        self.validate_online, self.dispatch = validate_online, dispatch
        self.database = database.absolute()
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.database.is_symlink():
            raise ValueError("execution ledger cannot be a symbolic link")
        with closing(self._connection()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("""CREATE TABLE IF NOT EXISTS executions (
                nonce TEXT PRIMARY KEY, tenant TEXT NOT NULL, principal TEXT NOT NULL,
                credential TEXT NOT NULL, task TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                digest TEXT NOT NULL, effect_digest TEXT NOT NULL, amount TEXT NOT NULL,
                status TEXT NOT NULL, result TEXT,
                UNIQUE(tenant, principal, credential, task, idempotency_key))""")
        os.chmod(self.database, 0o600)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        return connection

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
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                (
                    "SELECT * FROM executions WHERE nonce=? OR "
                    "(tenant=? AND principal=? AND credential=? AND task=? AND idempotency_key=?)"
                ),
                (grant.nonce, *scope, action.idempotency_key),
            ).fetchone()
            if existing is not None:
                connection.rollback()
                if existing["digest"] != grant.action_digest:
                    raise AuthorizationError("execution key is bound to a different effect")
                if existing["status"] == "succeeded":
                    return {
                        "nonce": existing["nonce"],
                        "status": "succeeded",
                        "result": existing["result"],
                        "replayed": True,
                    }
                if existing["status"] == "not_dispatched":
                    raise AuthorizationError(
                        "previous grant was rejected before dispatch; use a new key"
                    )
                raise ExecutionUnknown("an execution is pending or unknown; do not blindly retry")
            if (
                not grant.repeatable
                and connection.execute(
                    (
                        "SELECT 1 FROM executions WHERE tenant=? AND principal=? "
                        "AND credential=? AND task=? AND effect_digest=? "
                        "AND status!='not_dispatched'"
                    ),
                    (*scope, effect_digest),
                ).fetchone()
            ):
                connection.rollback()
                raise AuthorizationError("identical effect already reserved under another key")
            spent = sum(
                (
                    Decimal(row[0])
                    for row in connection.execute(
                        (
                            "SELECT amount FROM executions WHERE tenant=? AND principal=? "
                            "AND credential=? AND task=? AND status!='not_dispatched'"
                        ),
                        scope,
                    )
                ),
                Decimal(0),
            )
            if grant.budget_limit is not None and spent + amount > Decimal(grant.budget_limit):
                connection.rollback()
                raise AuthorizationError("task budget is already spent or reserved")
            connection.execute(
                "INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    grant.nonce,
                    *scope,
                    action.idempotency_key,
                    grant.action_digest,
                    effect_digest,
                    str(amount),
                    "pending",
                    None,
                ),
            )
            connection.commit()
        try:
            self.validate_online(self.identity, action, grant)
        except BaseException:
            with closing(self._connection()) as connection:
                connection.execute(
                    "UPDATE executions SET status='not_dispatched' WHERE nonce=?", (grant.nonce,)
                )
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
            with closing(self._connection()) as connection:
                connection.execute(
                    "UPDATE executions SET status='unknown' WHERE nonce=?", (grant.nonce,)
                )
            raise ExecutionUnknown(
                "dispatch outcome is unknown; reconcile with the provider before retry"
            ) from exc
        with closing(self._connection()) as connection:
            connection.execute(
                "UPDATE executions SET status='succeeded', result=? WHERE nonce=?",
                (safe_result, grant.nonce),
            )
        return {
            "nonce": grant.nonce,
            "status": "succeeded",
            "result": safe_result,
            "replayed": False,
        }
