"""Transactional signed authority snapshots for the bounded single-host profile.

SQLite serializes writers across processes. This backend favors a small auditable
contract over throughput: each outer transaction loads/verifies/saves a bounded snapshot.
The private database and externally supplied signing seed are trusted infrastructure.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from traceguard.control.models import AuditEvent, DecisionResponse, PolicyVersion, Review
from traceguard.control.service import ControlPlane, DecisionReceipt
from traceguard.control.signing import Signer, canonical, verify


class CapacityError(RuntimeError):
    """Admission is refused rather than dropping security-critical state."""


class SQLiteControlPlane(ControlPlane):
    def __init__(
        self,
        database: Path,
        signing_key: bytes,
        *,
        initialize: bool = False,
        key_id: str = "authority-ed25519-v1",
        max_entries: int = 10_000,
        max_state_bytes: int = 33_554_432,
    ) -> None:
        super().__init__(signing_key, key_id=key_id)
        self.database = database.absolute()
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.database.is_symlink() or (not initialize and not self.database.is_file()):
            raise ValueError("private initialized authority database is required")
        self._state_signer = Signer(signing_key, "traceguard-authority-state-v1")
        self.max_entries, self.max_state_bytes = max_entries, max_state_bytes
        self._depth = 0
        self._revision = 0
        self._allow_initialize = initialize
        if initialize:
            with closing(self._connect()) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS authority "
                    "(id INTEGER PRIMARY KEY CHECK(id=1), body TEXT, signature TEXT)"
                )
            os.chmod(self.database, 0o600)
        with self.transaction():
            pass
        self._allow_initialize = False

    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _dump(self) -> dict:
        return {
            "schema": 1,
            "key_id": self.key_id,
            "revision": self._revision,
            "policies": {
                key: [v.model_dump(mode="json") for v in values]
                for key, values in self._policies.items()
            },
            "audits": {
                key: [v.model_dump(mode="json") for v in values]
                for key, values in self._audits.items()
            },
            "heads": self._audit_heads,
            "epochs": self._epochs,
            "reviews": {key: v.model_dump(mode="json") for key, v in self._reviews.items()},
            "receipts": [
                [
                    list(key),
                    value.digest,
                    value.epoch,
                    value.expires_at.isoformat(),
                    value.result.model_dump(mode="json"),
                ]
                for key, value in self._idempotent.items()
            ],
            "tasks": [[list(key), asdict(value)] for key, value in self._execution_tasks.items()],
            "issued": self._execution_issued,
            "revoked": [list(key) for key in sorted(self._revoked_credentials)],
            "suspended": sorted(self._suspended_tenants),
        }

    def _load(self, data: dict) -> None:
        from traceguard.control.execution import RegisteredTask
        from traceguard.policy.kernel import CompiledAuthority

        if data.get("schema") != 1 or data.get("key_id") != self.key_id:
            raise ValueError("unsupported authority storage schema")
        self._revision = data["revision"]
        self._policies = {
            key: [PolicyVersion.model_validate(v) for v in values]
            for key, values in data["policies"].items()
        }
        self._audits = {
            key: [AuditEvent.model_validate(v) for v in values]
            for key, values in data["audits"].items()
        }
        self._audit_heads = {key: tuple(value) for key, value in data["heads"].items()}
        self._epochs = data["epochs"]
        self._reviews = {key: Review.model_validate(v) for key, v in data["reviews"].items()}
        self._idempotent = {
            tuple(key): DecisionReceipt(
                digest,
                epoch,
                datetime.fromisoformat(expires),
                DecisionResponse.model_validate(result),
            )
            for key, digest, epoch, expires, result in data["receipts"]
        }
        self._execution_tasks = {
            tuple(key): RegisteredTask(
                value["principal"],
                value["credential"],
                CompiledAuthority(**value["compiled"]),
                value["adapter_digest"],
                value.get("execution_domain", ""),
            )
            for key, value in data["tasks"]
        }
        self._execution_issued = data["issued"]
        self._revoked_credentials = {tuple(key) for key in data["revoked"]}
        self._suspended_tenants = set(data["suspended"])

    def _prune_and_bound(self) -> None:
        now = datetime.now(UTC)
        self._idempotent = {key: v for key, v in self._idempotent.items() if v.expires_at > now}
        self._reviews = {key: v for key, v in self._reviews.items() if v.expires_at > now}
        self._execution_issued = {
            key: v
            for key, v in self._execution_issued.items()
            if datetime.fromisoformat(json.loads(v)["expires_at"]) > now
        }
        collections = [
            self._idempotent,
            self._reviews,
            self._execution_tasks,
            self._execution_issued,
            self._revoked_credentials,
            self._policies,
        ]
        if any(len(value) > self.max_entries for value in collections) or any(
            len(values) > self.max_entries
            for values in [*self._policies.values(), *self._audits.values()]
        ):
            raise CapacityError("authority quota reached; export/archive before further admission")

    @contextmanager
    def transaction(self):
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT body,signature FROM authority WHERE id=1"
                ).fetchone()
                if row is None and not self._allow_initialize:
                    raise ValueError("authority state was lost; explicit recovery is required")
                if row is not None:
                    if len(row[0].encode()) > self.max_state_bytes:
                        raise CapacityError("authority state exceeds configured size limit")
                    data = json.loads(row[0])
                    if not verify(self._state_signer.public_key, data, row[1]):
                        raise ValueError("authority state signature is invalid; refusing recovery")
                    self._load(data)
                before = self._dump()
                self._depth = 1
                try:
                    self._prune_and_bound()
                    yield
                    self._prune_and_bound()
                    self._revision += 1
                    after = self._dump()
                    body = canonical(after)
                    if len(body) > self.max_state_bytes:
                        raise CapacityError("authority state size quota reached")
                    connection.execute(
                        "INSERT OR REPLACE INTO authority VALUES(1,?,?)",
                        (body.decode(), self._state_signer.sign(after)),
                    )
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    self._load(before)
                    raise
                finally:
                    self._depth = 0

    def backup(self, destination: Path) -> None:
        if destination.exists():
            raise ValueError("backup destination must be new")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.transaction():
            pass
        with self._lock, closing(self._connect()) as source:
            with closing(sqlite3.connect(destination)) as target:
                source.backup(target)
        os.chmod(destination, 0o600)

    def rekey(
        self, destination: Path, new_seed: bytes, new_key_id: str, actor
    ) -> SQLiteControlPlane:
        """Offline operator workflow: stop/fence all services before switching databases."""
        if destination.exists() or new_key_id == self.key_id:
            raise ValueError("rotation requires a new database and key identity")
        with self.transaction():
            for tenant in self._policies:
                from traceguard.control.models import Role

                self._require(actor, Role.ADMIN, tenant)
            snapshot = self._dump()
            snapshot["key_id"] = new_key_id
            snapshot["issued"], snapshot["receipts"], snapshot["reviews"] = {}, [], {}
            snapshot["epochs"] = {key: value + 1 for key, value in self._epochs.items()}
            replacement = SQLiteControlPlane(
                destination,
                new_seed,
                key_id=new_key_id,
                initialize=True,
                max_entries=self.max_entries,
                max_state_bytes=self.max_state_bytes,
            )
            with replacement.transaction():
                replacement._load(snapshot)
        return replacement
