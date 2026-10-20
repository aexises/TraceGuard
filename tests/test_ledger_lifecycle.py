import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest
from test_execution_grants import configured

from traceguard.control.service import AuthorizationError
from traceguard.ledger import ExecutionLedger, ExecutionUnknown


def reserve(ledger, nonce="first", *, credential="credential", amount="60"):
    return ledger.reserve(
        scope=("tenant", "agent", credential, "task"),
        nonce=nonce,
        idempotency_key=nonce,
        digest=nonce,
        effect_digest=nonce,
        amount=Decimal(amount),
        budget_limit="100",
    )


@pytest.mark.parametrize("failure", ["missing", "empty", "wrong", "schema", "deleted-row"])
def test_normal_open_never_recreates_or_accepts_invalid_store(tmp_path, failure):
    path = tmp_path / "effects.db"
    expected = ExecutionLedger.provision(path)
    if failure == "missing":
        path.unlink()
    elif failure == "empty":
        path.write_bytes(b"")
    elif failure == "wrong":
        path.unlink()
        ExecutionLedger.provision(path)
    else:
        with sqlite3.connect(path) as connection:
            connection.execute(
                "UPDATE ledger_metadata SET schema=999"
                if failure == "schema"
                else "DELETE FROM ledger_metadata"
            )
    with pytest.raises(ValueError):
        ExecutionLedger(path, expected_store_id=expected)
    if failure == "missing":
        assert not path.exists()


def test_running_instance_checks_store_identity_on_every_connection(tmp_path):
    path = tmp_path / "effects.db"
    ledger = ExecutionLedger(path, expected_store_id=ExecutionLedger.provision(path))
    path.unlink()
    ExecutionLedger.provision(path)
    with pytest.raises(ValueError):
        reserve(ledger)


def test_lost_store_cannot_dispatch_same_still_valid_grant_again(tmp_path):
    _, issuer, agent, factory, action, effects = configured(tmp_path)
    grant = issuer.issue(agent, action, "executor")
    instance = factory()
    instance.execute(agent, action, grant)
    instance.database.unlink()
    with pytest.raises(ValueError):
        factory().execute(agent, action, grant)
    assert len(effects) == 1


def test_grant_cannot_execute_in_an_independent_budget_domain(tmp_path):
    _, issuer, agent, factory, action, effects = configured(tmp_path)
    instance = factory()
    wrong = tmp_path / "wrong.db"
    instance.ledger = ExecutionLedger(wrong, expected_store_id=ExecutionLedger.provision(wrong))
    with pytest.raises(AuthorizationError):
        instance.execute(agent, action, issuer.issue(agent, action, "executor"))
    assert not effects


def test_distinct_concurrent_reservations_allow_only_one_pending_effect(tmp_path):
    path = tmp_path / "effects.db"
    identity = ExecutionLedger.provision(path)
    instances = [ExecutionLedger(path, expected_store_id=identity) for _ in range(2)]
    start = threading.Barrier(2)

    def attempt(index):
        start.wait()
        try:
            reserve(instances[index], str(index))
            return "reserved"
        except ExecutionUnknown:
            return "held"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, range(2))) == ["held", "reserved"]


def test_unknown_holds_changed_actions_and_credential_aliases_across_restart(tmp_path):
    path = tmp_path / "effects.db"
    identity = ExecutionLedger.provision(path)
    ledger = ExecutionLedger(path, expected_store_id=identity)
    reserve(ledger)
    ledger.finish("first", "unknown")
    restarted = ExecutionLedger(path, expected_store_id=identity)
    with pytest.raises(ExecutionUnknown):
        reserve(restarted, "different", credential="different-credential", amount="1")


def test_known_complete_budget_and_fenced_reconciliation_preserve_utility(tmp_path):
    path = tmp_path / "effects.db"
    ledger = ExecutionLedger(path, expected_store_id=ExecutionLedger.provision(path))
    reserve(ledger)
    with pytest.raises(ValueError, match="fence"):
        ledger.reconcile(
            "first",
            status="succeeded",
            result="receipt",
            actor="operator",
            provider_reference="provider-1",
        )
    ledger.reconcile(
        "first",
        status="succeeded",
        result="receipt",
        actor="operator",
        provider_reference="provider-1",
        pending_worker_fenced=True,
    )
    reserve(ledger, "second", amount="40")
    ledger.finish("second", "succeeded", "receipt-2")
    with pytest.raises(AuthorizationError, match="budget"):
        reserve(ledger, "third", amount="1")


def legacy_ledger(path):
    # Build the exact pre-C02 schema using the provisioning definition, then remove metadata.
    identity = ExecutionLedger.provision(path)
    ledger = ExecutionLedger(path, expected_store_id=identity)
    reserve(ledger)
    ledger.finish("first", "unknown")
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE ledger_metadata")


def test_fenced_legacy_migration_preserves_unknown_effect_and_verified_backup(tmp_path):
    path, backup = tmp_path / "legacy.db", tmp_path / "verified-backup.db"
    legacy_ledger(path)
    with pytest.raises(ValueError):
        ExecutionLedger.migrate_legacy(
            path, backup=backup, store_id="approved-domain", workers_fenced=False
        )
    ExecutionLedger.migrate_legacy(
        path, backup=backup, store_id="approved-domain", workers_fenced=True
    )
    ledger = ExecutionLedger(path, expected_store_id="approved-domain")
    assert ledger.lookup("first")["amount"] == "60"
    with pytest.raises(ExecutionUnknown):
        reserve(ledger, "changed", amount="1")
    with sqlite3.connect(backup) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT nonce,status FROM executions").fetchall() == [
            ("first", "unknown")
        ]


def test_failed_migration_rolls_back_and_retains_original(tmp_path):
    path, backup = tmp_path / "legacy.db", tmp_path / "backup.db"
    legacy_ledger(path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unsupported (value TEXT)")
    with pytest.raises(ValueError, match="supported legacy"):
        ExecutionLedger.migrate_legacy(
            path, backup=backup, store_id="approved-domain", workers_fenced=True
        )
    with sqlite3.connect(path) as connection:
        assert not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='ledger_metadata'"
        ).fetchone()
        assert connection.execute("SELECT status FROM executions").fetchone()[0] == "unknown"


def test_resolving_one_legacy_unknown_never_clears_another(tmp_path):
    path = tmp_path / "legacy.db"
    legacy_ledger(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO executions SELECT 'second',tenant,principal,credential,task,'second',"
            "'second','second','1',status,result FROM executions"
        )
    ExecutionLedger.migrate_legacy(
        path, backup=tmp_path / "backup.db", store_id="domain", workers_fenced=True
    )
    ledger = ExecutionLedger(path, expected_store_id="domain")
    ledger.reconcile(
        "first",
        status="not_dispatched",
        result=None,
        actor="operator",
        provider_reference="provider-1",
    )
    with pytest.raises(ExecutionUnknown):
        reserve(ledger, "third", amount="1")
