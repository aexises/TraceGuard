import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from test_execution_grants import actor, configured

from traceguard.control.execution import ExecutionAuthority
from traceguard.control.models import (
    PolicyDraft,
    PolicyRule,
    ReviewResolution,
    Role,
    RuleMatch,
    TaskRegistration,
)
from traceguard.control.service import AuthorizationError
from traceguard.control.storage import CapacityError, SQLiteControlPlane

KEY = b"test-only-authority-seed-" + b"x" * 32


def registration(task="new-task"):
    return TaskRegistration(
        task_id=task,
        agent_subject="agent",
        service_key_id="agent-key",
        execution_domain="test-approved-domain",
        authority={"enforcement_mode": "strict", "allowed_tools": ["calculator"]},
        adapter_digest="a" * 64,
        tool_schemas={"calculator": {"type": "object", "properties": {}}},
    )


@pytest.mark.parametrize("concurrent", [False, True])
def test_registration_authorizes_after_loading_committed_revocation(tmp_path, concurrent):
    path = tmp_path / "authority.db"
    stale = SQLiteControlPlane(path, KEY, initialize=True)
    revoker = SQLiteControlPlane(path, KEY)
    admin = actor("old-admin", Role.ADMIN, "old-admin-key")
    entered = threading.Event()

    def register():
        entered.set()
        with pytest.raises(AuthorizationError, match="revoked"):
            ExecutionAuthority(stale).register("tenant", admin, registration())

    if concurrent:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with revoker.transaction():
                revoker.revoke_credential("tenant", actor("operator", Role.ADMIN), "old-admin-key")
                future = pool.submit(register)
                assert entered.wait(2)
            future.result(timeout=5)
    else:
        revoker.revoke_credential("tenant", actor("operator", Role.ADMIN), "old-admin-key")
        register()
    restored = SQLiteControlPlane(path, KEY)
    assert not restored._execution_tasks
    assert not any(e.event_type == "task.registered" for e in restored._audits["tenant"])


@pytest.mark.parametrize("invalid", ["tenant", "role", "audit"])
def test_registration_denial_and_failure_leave_no_task_or_audit(tmp_path, monkeypatch, invalid):
    path = tmp_path / "authority.db"
    plane = SQLiteControlPlane(path, KEY, initialize=True)
    admin = actor("author", Role.ADMIN)
    if invalid == "tenant":
        admin.tenant_ids = {"different-tenant"}
    elif invalid == "role":
        admin.roles = {Role.AGENT}
    else:

        def fail(*args, **kwargs):
            raise OSError("injected audit failure")

        monkeypatch.setattr(plane, "_append_audit", fail)
    with pytest.raises((AuthorizationError, OSError)):
        ExecutionAuthority(plane).register("tenant", admin, registration())
    restored = SQLiteControlPlane(path, KEY)
    assert not restored._execution_tasks
    assert not restored._audits


def test_valid_registration_remains_available_to_current_administrator(tmp_path):
    plane = SQLiteControlPlane(tmp_path / "authority.db", KEY, initialize=True)
    digest = ExecutionAuthority(plane).register(
        "tenant", actor("author", Role.ADMIN), registration()
    )
    restored = SQLiteControlPlane(plane.database, KEY)
    assert restored._execution_tasks[("tenant", "new-task")].compiled.digest == digest
    assert restored.verify_audit_chain("tenant")


def test_legacy_domain_requires_fenced_admin_reapproval_and_invalidates_grants(tmp_path):
    plane = SQLiteControlPlane(tmp_path / "authority.db", KEY, initialize=True)
    _, issuer, agent, factory, action, _ = configured(tmp_path, control=plane)
    old_grant = issuer.issue(agent, action, "executor")
    with plane.transaction():
        key = ("tenant", "task")
        plane._execution_tasks[key] = replace(plane._execution_tasks[key], execution_domain="")
    restarted = ExecutionAuthority(SQLiteControlPlane(plane.database, KEY))
    with pytest.raises(AuthorizationError, match="legacy"):
        restarted.issue(agent, action, "executor")
    with pytest.raises(ValueError, match="fenced"):
        restarted.bind_legacy_domain(
            "tenant",
            actor("author", Role.ADMIN),
            "task",
            old_grant.execution_domain,
            workers_fenced=False,
        )
    with pytest.raises(AuthorizationError):
        restarted.bind_legacy_domain(
            "tenant", agent, "task", old_grant.execution_domain, workers_fenced=True
        )
    restarted.bind_legacy_domain(
        "tenant",
        actor("author", Role.ADMIN),
        "task",
        old_grant.execution_domain,
        workers_fenced=True,
    )
    with pytest.raises(AuthorizationError):
        factory().execute(agent, action, old_grant)
    new_grant = restarted.issue(agent, action, "executor")
    assert factory().execute(agent, action, new_grant)["status"] == "succeeded"
    with pytest.raises(ValueError, match="immutable"):
        restarted.bind_legacy_domain(
            "tenant", actor("author", Role.ADMIN), "task", "wrong-domain", workers_fenced=True
        )


def test_restart_preserves_registered_authority_grants_audit_and_revocation(tmp_path):
    path = tmp_path / "state/authority.db"
    first = SQLiteControlPlane(path, KEY, initialize=True)
    _, issuer, agent, factory, action, _ = configured(tmp_path, control=first)
    grant = issuer.issue(agent, action, "executor")
    restored = SQLiteControlPlane(path, KEY)
    replacement = ExecutionAuthority(restored)
    replacement.validate(actor("executor", Role.EXECUTOR, "executor-key"), action, grant)
    assert restored.verify_audit_chain("tenant")
    restored.revoke_credential("tenant", actor("author", Role.ADMIN), "agent-key")
    with pytest.raises(AuthorizationError, match="revoked|invalid"):
        factory().execute(agent, action, grant)
    again = SQLiteControlPlane(path, KEY)
    with pytest.raises(AuthorizationError, match="revoked"):
        again.evaluate(agent, action.model_copy(update={"idempotency_key": "fresh-key"}))


def test_review_can_resume_after_restart_and_database_backup(tmp_path):
    path = tmp_path / "state/authority.db"
    plane = SQLiteControlPlane(path, KEY, initialize=True)
    _, issuer, agent, _, action, _ = configured(tmp_path, review=True, control=plane)
    review_id = plane.evaluate(agent, action).review_id
    backup = tmp_path / "backup/authority.db"
    plane.backup(backup)
    restored = SQLiteControlPlane(backup, KEY)
    restored.resolve_review(
        "tenant",
        actor("reviewer", Role.REVIEWER),
        review_id,
        ReviewResolution.ALLOW,
        "approved exact action",
    )
    grant = ExecutionAuthority(restored).issue(agent, action, "executor", review_id)
    assert grant.task_id == action.task_id


def test_quota_failure_rolls_back_policy_and_audit_atomically(tmp_path):
    path = tmp_path / "authority.db"
    plane = SQLiteControlPlane(path, KEY, initialize=True, max_entries=2)
    author = actor("author", Role.ADMIN)
    draft = PolicyDraft(
        name="test",
        rules=[
            PolicyRule(
                name="deny",
                priority=1,
                match=RuleMatch(),
                decision="BLOCK",
                reason="deny",
            )
        ],
    )
    policy = plane.create_draft("tenant", author, draft)
    plane.submit_policy("tenant", author, policy.policy_id)
    with pytest.raises(CapacityError):
        plane.approve_policy("tenant", actor("approver", Role.APPROVER), policy.policy_id)
    restored = SQLiteControlPlane(path, KEY, max_entries=2)
    assert restored.active_policy("tenant") is None
    assert restored.verify_audit_chain("tenant")


@pytest.mark.parametrize("corruption", ["signature", "lost_row", "wrong_key"])
def test_corrupt_or_missing_state_never_reinitializes_silently(tmp_path, corruption):
    path = tmp_path / "authority.db"
    SQLiteControlPlane(path, KEY, initialize=True)
    if corruption != "wrong_key":
        with sqlite3.connect(path) as connection:
            if corruption == "lost_row":
                connection.execute("DELETE FROM authority")
            else:
                body = json.loads(connection.execute("SELECT body FROM authority").fetchone()[0])
                body["epochs"] = {"tenant": 999}
                connection.execute("UPDATE authority SET body=?", (json.dumps(body),))
    with pytest.raises(ValueError):
        SQLiteControlPlane(path, b"z" * 32 if corruption == "wrong_key" else KEY)


def test_two_instances_serialize_policy_updates_without_lost_state(tmp_path):
    path = tmp_path / "authority.db"
    planes = [SQLiteControlPlane(path, KEY, initialize=True), SQLiteControlPlane(path, KEY)]

    def create(pair):
        index, plane = pair
        return plane.create_draft(
            "tenant",
            actor(f"author-{index}", Role.ADMIN),
            PolicyDraft(
                name="test",
                rules=[
                    PolicyRule(
                        name="deny", priority=1, match=RuleMatch(), decision="BLOCK", reason="deny"
                    )
                ],
            ),
        ).version

    with ThreadPoolExecutor(max_workers=2) as pool:
        versions = list(pool.map(create, enumerate(planes)))
    assert sorted(versions) == [1, 2]
    restored = SQLiteControlPlane(path, KEY)
    assert len(restored._policies["tenant"]) == 2


def test_offline_rekey_preserves_policy_and_revokes_old_grants(tmp_path):
    plane = SQLiteControlPlane(tmp_path / "old.db", KEY, initialize=True)
    _, issuer, agent, _, action, _ = configured(tmp_path, control=plane)
    grant = issuer.issue(agent, action, "executor")
    replacement = plane.rekey(
        tmp_path / "new.db",
        b"new-test-only-key-" + b"y" * 32,
        "rotated-key-v2",
        actor("operator", Role.ADMIN),
    )
    assert replacement.active_policy("tenant") is not None
    assert replacement.verify_audit_chain("tenant")
    with pytest.raises(AuthorizationError):
        ExecutionAuthority(replacement).validate(
            actor("executor", Role.EXECUTOR, "executor-key"),
            action,
            grant,
        )
    with pytest.raises(ValueError):
        SQLiteControlPlane(tmp_path / "new.db", KEY)


def test_tenant_kill_switch_survives_restart_and_resumption_revokes_old_grants(tmp_path):
    path = tmp_path / "authority.db"
    plane = SQLiteControlPlane(path, KEY, initialize=True)
    _, issuer, agent, factory, action, _ = configured(tmp_path, control=plane)
    grant = issuer.issue(agent, action, "executor")
    plane.suspend_tenant("tenant", actor("operator", Role.ADMIN))
    replacement = SQLiteControlPlane(path, KEY)
    with pytest.raises(AuthorizationError, match="suspended"):
        replacement.evaluate(agent, action)
    replacement.suspend_tenant("tenant", actor("operator", Role.ADMIN), False)
    with pytest.raises(AuthorizationError):
        factory().execute(agent, action, grant)
