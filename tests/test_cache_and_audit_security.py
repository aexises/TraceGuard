from datetime import UTC, datetime
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest
from test_control_plane import active_plane, actor

from traceguard.control.models import ActionRequest, Role
from traceguard.control.signing import verify
from traceguard.sdk import PolicyUnavailable, SignedPolicyCache, TraceGuardClient


def request():
    return ActionRequest(
        tenant_id="tenant-a",
        idempotency_key="security-cache",
        kind="http",
        operation="GET",
        target="https://api.example.test/a",
    )


def cache_for(plane, **changes):
    kwargs = dict(
        tenant_id="tenant-a", audience="agent", service_key_id="key-1", key_id=plane.key_id
    )
    return SignedPolicyCache(plane.policy_public_key, **{**kwargs, **changes})


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant_id": "other"},
        {"audience": "other"},
        {"service_key_id": "other"},
        {"key_id": "other"},
    ],
)
def test_bundle_is_bound_to_verifier_scope(changes):
    plane, agent = active_plane()
    with pytest.raises(PolicyUnavailable):
        cache_for(plane, **changes).install(plane.signed_bundle("tenant-a", agent))


def test_installed_bundle_is_an_immutable_verified_snapshot():
    plane, agent = active_plane()
    bundle = plane.signed_bundle("tenant-a", agent)
    cache = cache_for(plane)
    cache.install(bundle)
    bundle.policy.draft.rules[0].match.target_prefix = "https://outside.test/"
    assert cache.evaluate(request()).from_cache
    with pytest.raises(PolicyUnavailable):
        cache.evaluate(request().model_copy(update={"target": "https://outside.test/"}))


@pytest.mark.parametrize("status", [301, 401, 403, 409, 422, 429, 500, 503])
def test_explicit_http_rejection_never_falls_back(status):
    plane, agent = active_plane()
    cache = cache_for(plane)
    cache.install(plane.signed_bundle("tenant-a", agent))
    client = TraceGuardClient("https://control.test", "test", cache)
    with patch(
        "traceguard.sdk.urlopen",
        side_effect=HTTPError("https://control.test", status, "denied", {}, None),
    ):
        with pytest.raises(PolicyUnavailable):
            client.evaluate(request())
    assert not client._offline_events


def test_offline_read_works_and_reconciliation_preserves_unacknowledged_queue():
    plane, agent = active_plane()
    cache = cache_for(plane)
    cache.install(plane.signed_bundle("tenant-a", agent))
    client = TraceGuardClient("https://control.test", "test", cache)
    with patch("traceguard.sdk.urlopen", side_effect=URLError("offline")):
        assert client.evaluate(request()).from_cache
        with pytest.raises(URLError):
            client.reconcile()
    assert len(client._offline_events) == 1
    with pytest.raises(PolicyUnavailable):
        cache.evaluate(request().model_copy(update={"operation": "POST"}))


@pytest.mark.parametrize(
    "field,value", [("created_at", datetime(2000, 1, 1, tzinfo=UTC)), ("audit_id", "changed")]
)
def test_audit_event_metadata_is_hashed_and_export_refuses_corruption(field, value):
    plane, _ = active_plane()
    setattr(plane._audits["tenant-a"][0], field, value)
    assert not plane.verify_audit_chain("tenant-a")
    with pytest.raises(ValueError, match="integrity"):
        plane.export_audit("tenant-a", actor("auditor", Role.AUDITOR))


def test_audit_privacy_signing_separation_and_local_truncation_detection():
    plane, agent = active_plane()
    action = request()
    action.arguments = {
        "password": "CANARY_PASSWORD",
        "headers": {"Authorization": "Bearer CANARY_TOKEN"},
    }
    plane.evaluate(agent, action)
    exported = plane.export_audit("tenant-a", actor("auditor", Role.AUDITOR))
    assert "CANARY_PASSWORD" not in str(exported) and "CANARY_TOKEN" not in str(exported)
    payload = {
        key: value
        for key, value in exported.items()
        if key not in {"signature", "key_id", "algorithm"}
    }
    assert verify(plane.audit_public_key, payload, exported["signature"])
    assert not verify(plane.policy_public_key, payload, exported["signature"])
    plane._audits["tenant-a"].pop()
    assert not plane.verify_audit_chain("tenant-a")


def test_valid_signature_does_not_allow_epoch_rollback_or_unscoped_operations():
    plane, agent = active_plane()
    old = plane.signed_bundle("tenant-a", agent)
    cache = cache_for(plane)
    author = actor("author", Role.ADMIN)
    new = plane.create_draft("tenant-a", author, old.policy.draft)
    plane.submit_policy("tenant-a", author, new.policy_id)
    plane.approve_policy("tenant-a", actor("approver", Role.APPROVER), new.policy_id)
    cache.install(plane.signed_bundle("tenant-a", agent))
    with pytest.raises(PolicyUnavailable, match="epoch"):
        cache.install(old)
    agent.allowed_operations = frozenset({"POST"})
    limited = plane.signed_bundle("tenant-a", agent)
    cache_for(plane).install(limited)
    other_cache = cache_for(plane)
    other_cache.install(limited)
    with pytest.raises(PolicyUnavailable):
        other_cache.evaluate(request())
