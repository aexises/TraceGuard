"""Shared transactional reservation state for embedded and isolated execution."""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from decimal import Decimal
from pathlib import Path

from traceguard.control.service import AuthorizationError


class ExecutionUnknown(RuntimeError):
    """An effect may have happened; authoritative reconciliation is required."""


class ExecutionLedger:
    def __init__(self, database: Path) -> None:
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
            connection.execute("""CREATE TABLE IF NOT EXISTS reconciliations (
                nonce TEXT NOT NULL, actor TEXT NOT NULL, status TEXT NOT NULL,
                provider_reference TEXT NOT NULL,
                resolved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        os.chmod(self.database, 0o600)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def reserve(
        self,
        *,
        scope: tuple[str, str, str, str],
        nonce: str,
        idempotency_key: str,
        digest: str,
        effect_digest: str,
        amount: Decimal = Decimal(0),
        budget_limit: str | None = None,
        repeatable: bool = False,
    ) -> dict | None:
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                (
                    "SELECT * FROM executions WHERE nonce=? OR "
                    "(tenant=? AND principal=? AND credential=? AND task=? AND idempotency_key=?)"
                ),
                (nonce, *scope, idempotency_key),
            ).fetchone()
            if existing is not None:
                connection.rollback()
                existing_scope = tuple(
                    existing[key] for key in ("tenant", "principal", "credential", "task")
                )
                if existing["digest"] != digest or existing_scope != scope:
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
            if connection.execute(
                "SELECT 1 FROM executions WHERE tenant=? AND principal=? AND credential=? "
                "AND task=? AND effect_digest=? AND status IN ('pending','unknown')",
                (*scope, effect_digest),
            ).fetchone():
                raise ExecutionUnknown("identical effect is pending or unknown")
            if (
                not repeatable
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
            if budget_limit is not None and spent + amount > Decimal(budget_limit):
                connection.rollback()
                raise AuthorizationError("task budget is already spent or reserved")
            connection.execute(
                "INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    nonce,
                    *scope,
                    idempotency_key,
                    digest,
                    effect_digest,
                    str(amount),
                    "pending",
                    None,
                ),
            )
            connection.commit()

    def finish(self, nonce: str, status: str, result: str | None = None) -> None:
        if status not in {"succeeded", "unknown", "not_dispatched"}:
            raise ValueError("invalid execution status")
        with closing(self._connection()) as connection:
            changed = connection.execute(
                "UPDATE executions SET status=?, result=? WHERE nonce=? AND status='pending'",
                (status, result, nonce),
            ).rowcount
            if changed != 1:
                raise ExecutionUnknown("reservation changed or was lost before completion")

    def lookup(self, nonce: str) -> dict:
        with closing(self._connection()) as connection:
            row = connection.execute("SELECT * FROM executions WHERE nonce=?", (nonce,)).fetchone()
        if row is None:
            raise KeyError("execution reservation not found")
        return dict(row)

    def reconcile(
        self, nonce: str, *, status: str, result: str | None, actor: str, provider_reference: str
    ) -> dict:
        if status not in {"succeeded", "not_dispatched"} or not provider_reference:
            raise ValueError("reconciliation requires a definitive verified provider receipt")
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE executions SET status=?, result=? WHERE nonce=? "
                "AND status IN ('unknown','pending')",
                (status, result, nonce),
            ).rowcount
            if changed != 1:
                raise ValueError("only an uncertain reservation can be reconciled")
            connection.execute(
                "INSERT INTO reconciliations(nonce, actor, status, provider_reference) "
                "VALUES (?,?,?,?)",
                (nonce, actor, status, provider_reference),
            )
            connection.commit()
        return self.lookup(nonce)
