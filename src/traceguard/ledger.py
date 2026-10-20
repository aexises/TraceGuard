"""Shared transactional reservation state for embedded and isolated execution."""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import closing
from decimal import Decimal
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from traceguard.control.service import AuthorizationError


class ExecutionUnknown(RuntimeError):
    """An effect may have happened; authoritative reconciliation is required."""


class ExecutionLedger:
    SCHEMA = 3

    def __init__(self, database: Path, *, expected_store_id: str) -> None:
        self.database = database.absolute()
        if not expected_store_id or len(expected_store_id) > 128:
            raise ValueError("trusted expected ledger identity is required")
        self.store_id = expected_store_id
        with closing(self._connection()) as connection:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("execution ledger integrity check failed")

    @classmethod
    def provision(cls, database: Path, *, store_id: str | None = None) -> str:
        """Trusted one-time deployment operation; never called by execution/open paths."""
        database = database.absolute()
        store_id = store_id or str(uuid4())
        if not store_id or len(store_id) > 128:
            raise ValueError("invalid store identity")
        database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""CREATE TABLE executions (
                nonce TEXT PRIMARY KEY, tenant TEXT NOT NULL, principal TEXT NOT NULL,
                credential TEXT NOT NULL, task TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                digest TEXT NOT NULL, effect_digest TEXT NOT NULL, amount TEXT NOT NULL,
                status TEXT NOT NULL, result TEXT,
                disposition TEXT NOT NULL DEFAULT 'review_required',
                result_policy TEXT NOT NULL DEFAULT '',
                UNIQUE(tenant, principal, credential, task, idempotency_key))""")
            connection.execute("""CREATE TABLE reconciliations (
                nonce TEXT NOT NULL, actor TEXT NOT NULL, status TEXT NOT NULL,
                provider_reference TEXT NOT NULL,
                resolved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
            cls._metadata(connection, store_id)
            connection.commit()
        cls(database, expected_store_id=store_id)
        return store_id

    @classmethod
    def _metadata(cls, connection: sqlite3.Connection, store_id: str) -> None:
        connection.execute(
            "CREATE TABLE ledger_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
            "schema INTEGER NOT NULL, store_id TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO ledger_metadata VALUES (1,?,?)", (cls.SCHEMA, store_id))

    @classmethod
    def migrate_legacy(
        cls, database: Path, *, backup: Path, store_id: str, workers_fenced: bool
    ) -> None:
        """Offline v1/v2 migration; fence old workers and retain the verified backup."""
        if not workers_fenced or not store_id or len(store_id) > 128:
            raise ValueError("migration requires fenced workers and an approved store identity")
        cls._check_file(database)
        descriptor = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with closing(cls._open_existing(database)) as source:
            with closing(sqlite3.connect(backup)) as destination:
                source.backup(destination)
                if destination.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("migration backup failed verification")
            source.execute("BEGIN IMMEDIATE")
            tables = {
                row[0]
                for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if tables not in (
                {"executions", "reconciliations"},
                {"executions", "reconciliations", "ledger_metadata"},
            ):
                raise ValueError("not a supported legacy ledger; no migration performed")
            # Require the exact known schema before modifying the fenced source.
            columns = [row[1] for row in source.execute("PRAGMA table_info(executions)")]
            if columns != [
                "nonce",
                "tenant",
                "principal",
                "credential",
                "task",
                "idempotency_key",
                "digest",
                "effect_digest",
                "amount",
                "status",
                "result",
            ]:
                raise ValueError("unsupported legacy execution schema")
            if "ledger_metadata" in tables:
                metadata = source.execute("SELECT schema,store_id FROM ledger_metadata").fetchall()
                if metadata != [(2, store_id)]:
                    raise ValueError("v2 migration requires its original approved identity")
            source.execute(
                "ALTER TABLE executions ADD COLUMN disposition "
                "TEXT NOT NULL DEFAULT 'review_required'"
            )
            source.execute(
                "ALTER TABLE executions ADD COLUMN result_policy TEXT NOT NULL DEFAULT ''"
            )
            if "ledger_metadata" in tables:
                source.execute("UPDATE ledger_metadata SET schema=?", (cls.SCHEMA,))
            else:
                cls._metadata(source, store_id)
            source.commit()

    @staticmethod
    def _check_file(database: Path) -> None:
        try:
            info = database.lstat()
        except FileNotFoundError as exc:
            raise ValueError("initialized execution ledger is missing; stop admission") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size == 0:
            raise ValueError("initialized private regular execution ledger is required")

    @staticmethod
    def _open_existing(database: Path) -> sqlite3.Connection:
        return sqlite3.connect(
            f"file:{quote(str(database.absolute()), safe='/')}?mode=rw",
            uri=True,
            timeout=5,
            isolation_level=None,
        )

    def _connection(self) -> sqlite3.Connection:
        self._check_file(self.database)
        connection = self._open_existing(self.database)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA synchronous=FULL")
            rows = connection.execute("SELECT schema, store_id FROM ledger_metadata").fetchall()
            if len(rows) != 1 or tuple(rows[0]) != (self.SCHEMA, self.store_id):
                raise ValueError("execution ledger schema or identity mismatch; stop admission")
        except (sqlite3.Error, ValueError) as exc:
            connection.close()
            raise ValueError(
                "execution ledger unavailable or incompatible; stop admission"
            ) from exc
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
        result_policy: str = "",
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
                existing_scope = tuple(
                    existing[key] for key in ("tenant", "principal", "credential", "task")
                )
                if existing["digest"] != digest or existing_scope != scope:
                    raise AuthorizationError("execution key is bound to a different effect")
                if existing["status"] == "succeeded":
                    disposition = existing["disposition"]
                    if disposition == "accepted_for_agent" and (
                        existing["result_policy"] != result_policy or existing["result"] is None
                    ):
                        disposition = "review_required"
                        connection.execute(
                            "UPDATE executions SET disposition=? WHERE nonce=?",
                            (disposition, existing["nonce"]),
                        )
                    connection.commit()
                    return {
                        "nonce": existing["nonce"],
                        "status": "succeeded",
                        "result": existing["result"]
                        if disposition == "accepted_for_agent"
                        else None,
                        "disposition": disposition,
                        "replayed": True,
                    }
                if existing["status"] == "not_dispatched":
                    raise AuthorizationError(
                        "previous grant was rejected before dispatch; use a new key"
                    )
                raise ExecutionUnknown("an execution is pending or unknown; do not blindly retry")
            if connection.execute(
                "SELECT 1 FROM executions WHERE tenant=? AND task=? "
                "AND (status IN ('pending','unknown') OR "
                "(status='succeeded' AND disposition!='accepted_for_agent'))",
                (scope[0], scope[3]),
            ).fetchone():
                raise ExecutionUnknown(
                    "task has a pending or unknown effect; reconcile before retry"
                )
            if (
                not repeatable
                and connection.execute(
                    (
                        "SELECT 1 FROM executions WHERE tenant=? AND task=? AND effect_digest=? "
                        "AND status!='not_dispatched'"
                    ),
                    (scope[0], scope[3], effect_digest),
                ).fetchone()
            ):
                connection.rollback()
                raise AuthorizationError("identical effect already reserved under another key")
            spent = sum(
                (
                    Decimal(row[0])
                    for row in connection.execute(
                        (
                            "SELECT amount FROM executions WHERE tenant=? AND task=? "
                            "AND status!='not_dispatched'"
                        ),
                        (scope[0], scope[3]),
                    )
                ),
                Decimal(0),
            )
            if budget_limit is not None and spent + amount > Decimal(budget_limit):
                connection.rollback()
                raise AuthorizationError("task budget is already spent or reserved")
            connection.execute(
                "INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    nonce,
                    *scope,
                    idempotency_key,
                    digest,
                    effect_digest,
                    str(amount),
                    "pending",
                    None,
                    "pending_review",
                    result_policy,
                ),
            )
            connection.commit()

    def finish(
        self,
        nonce: str,
        status: str,
        result: str | None = None,
        *,
        disposition: str = "review_required",
    ) -> None:
        if status not in {"succeeded", "unknown", "not_dispatched"}:
            raise ValueError("invalid execution status")
        if disposition not in {
            "pending_review",
            "accepted_for_agent",
            "withheld",
            "review_required",
        }:
            raise ValueError("invalid result disposition")
        if disposition == "accepted_for_agent" and (status != "succeeded" or result is None):
            raise ValueError("acceptance requires a succeeded execution and stored result")
        with closing(self._connection()) as connection:
            changed = connection.execute(
                "UPDATE executions SET status=?, result=?, disposition=? "
                "WHERE nonce=? AND status='pending'",
                (status, result, disposition, nonce),
            ).rowcount
            if changed != 1:
                raise ExecutionUnknown("reservation changed or was lost before completion")

    def decide_result(self, nonce: str, disposition: str, *, result_policy: str) -> None:
        """Complete the first review only; withheld decisions cannot be silently reconsidered."""
        if disposition not in {"accepted_for_agent", "withheld", "review_required"}:
            raise ValueError("invalid result disposition")
        with closing(self._connection()) as connection:
            changed = connection.execute(
                "UPDATE executions SET disposition=? WHERE nonce=? AND status='succeeded' "
                "AND disposition='pending_review' AND result_policy=? AND result IS NOT NULL",
                (disposition, nonce, result_policy),
            ).rowcount
            if changed != 1:
                raise ExecutionUnknown("result review changed or requires authorized recovery")

    def lookup(self, nonce: str) -> dict:
        with closing(self._connection()) as connection:
            row = connection.execute("SELECT * FROM executions WHERE nonce=?", (nonce,)).fetchone()
        if row is None:
            raise KeyError("execution reservation not found")
        return dict(row)

    def reconcile(
        self,
        nonce: str,
        *,
        status: str,
        result: str | None,
        actor: str,
        provider_reference: str,
        pending_worker_fenced: bool = False,
        disposition: str = "review_required",
    ) -> dict:
        if status not in {"succeeded", "not_dispatched"} or not provider_reference:
            raise ValueError("reconciliation requires a definitive verified provider receipt")
        if disposition not in {"accepted_for_agent", "withheld", "review_required"} or (
            disposition == "accepted_for_agent" and (status != "succeeded" or result is None)
        ):
            raise ValueError("invalid reconciliation result disposition")
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status FROM executions WHERE nonce=?", (nonce,)
            ).fetchone()
            if row is not None and row[0] == "pending" and not pending_worker_fenced:
                raise ValueError("fence the pending worker before reconciliation")
            changed = connection.execute(
                "UPDATE executions SET status=?, result=?, disposition=? WHERE nonce=? "
                "AND status IN ('unknown','pending')",
                (status, result, disposition, nonce),
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
