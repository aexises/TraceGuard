import copy
import ssl
import threading

import pytest

from traceguard.control.models import Role
from traceguard.control.service import AuthorizationError
from traceguard.isolated import AuthorityService, ExecutorService
from traceguard.isolation_fixture import prepare
from traceguard.mtls import BoundaryServer, MTLSClient, PeerIdentities, tls_context


def server(config, service):
    from pathlib import Path

    root = Path(config["identity_directory"])
    instance = BoundaryServer(
        ("127.0.0.1", 0),
        context=tls_context(
            root / "certificate.pem", root / "key.pem", root / "ca.pem", server=True
        ),
        identities=PeerIdentities(root / "peers.json"),
        dispatch=service,
    )
    thread = threading.Thread(
        target=instance.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    return instance, thread


def client(fixture, role, endpoint, port):
    root = fixture["directories"][role]
    return MTLSClient(
        f"https://localhost:{port}",
        tls_context(root / "certificate.pem", root / "key.pem", root / "ca.pem"),
        fixture["fingerprints"][endpoint],
    )


def test_live_mtls_enforces_identity_grant_scope_replay_and_revocation(tmp_path):
    fixture = prepare(tmp_path / "fixture")
    authority = AuthorityService(fixture["configs"]["authority"])
    issuer_server, issuer_thread = server(fixture["configs"]["authority"], authority)
    executor_config = fixture["configs"]["executor"]
    executor_config["issuer_url"] = f"https://localhost:{issuer_server.server_port}"
    executor = ExecutorService(executor_config)
    executor_server, executor_thread = server(executor_config, executor)
    try:
        issuer_client = client(fixture, "agent", "authority", issuer_server.server_port)
        executor_client = client(fixture, "agent", "executor", executor_server.server_port)
        task = fixture["task"]
        grant = issuer_client.request("/issue", task)
        payload = {"action": task["action"], "grant": grant}
        receipt = executor_client.request("/execute", payload)
        assert receipt["status"] == "succeeded"
        assert executor_client.request("/execute", payload)["replayed"]
        changed = copy.deepcopy(task)
        changed["action"]["idempotency_key"] = "changed-report-key"
        changed["action"]["arguments"]["path"] = "reports/unapproved.txt"
        with pytest.raises(AuthorizationError):
            issuer_client.request("/issue", changed)
        with pytest.raises(AuthorizationError):
            executor_client.request("/execute", {"action": changed["action"], "grant": grant})
        unknown = client(fixture, "unknown", "authority", issuer_server.server_port)
        with pytest.raises(AuthorizationError):
            unknown.request("/issue", task)
        unpinned = MTLSClient(
            f"https://localhost:{issuer_server.server_port}", issuer_client.context, "0" * 64
        )
        with pytest.raises(AuthorizationError):
            unpinned.request("/issue", task)
        no_certificate = MTLSClient(
            f"https://localhost:{issuer_server.server_port}",
            ssl.create_default_context(cafile=fixture["directories"]["agent"] / "ca.pem"),
            fixture["fingerprints"]["authority"],
        )
        with pytest.raises(OSError):
            no_certificate.request("/issue", task)
        admin = fixture["agent"].model_copy(
            update={"subject": "operator", "roles": {Role.ADMIN}, "service_key_id": "operator-key"}
        )
        authority.control.revoke_credential("tenant", admin, fixture["agent"].service_key_id)
        with pytest.raises(AuthorizationError):
            executor_client.request("/execute", payload)
    finally:
        for instance, thread in [
            (executor_server, executor_thread),
            (issuer_server, issuer_thread),
        ]:
            instance.shutdown()
            instance.server_close()
            thread.join(timeout=5)


def test_executor_refuses_unverified_adapter_artifact(tmp_path):
    fixture = prepare(tmp_path / "fixture")
    config = fixture["configs"]["executor"]
    config["adapter_digest"] = "0" * 64
    with pytest.raises(ValueError, match="adapter artifact"):
        ExecutorService(config)
