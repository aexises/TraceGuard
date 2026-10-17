"""Disposable hostile-agent conformance probe, run inside the unprivileged agent container."""

import copy
import json
import socket
import time
from pathlib import Path

from traceguard.control.service import AuthorizationError
from traceguard.mtls import MTLSClient, tls_context


def main() -> int:
    root = Path("/config")
    pins = json.loads((root / "services.json").read_text())
    context = tls_context(root / "certificate.pem", root / "key.pem", root / "ca.pem")
    issuer = MTLSClient("https://authority:9443", context, pins["authority"])
    executor = MTLSClient("https://executor:9443", context, pins["executor"])
    task = json.loads((root / "task.json").read_text())
    for attempt in range(30):
        try:
            grant = issuer.request("/issue", task)
            break
        except OSError:
            if attempt == 29:
                raise
            time.sleep(0.2)
    receipt = executor.request("/execute", {"action": task["action"], "grant": grant})
    assert receipt["status"] == "succeeded"
    replay = executor.request("/execute", {"action": task["action"], "grant": grant})
    assert replay["replayed"]

    def withheld(operation):
        try:
            operation()
        except AuthorizationError:
            return True
        raise AssertionError("an unapproved action was accepted")

    changed = copy.deepcopy(task)
    changed["action"]["idempotency_key"] = "different-effect-key"
    changed["action"]["arguments"]["path"] = "reports/unapproved.txt"
    scope_denied = withheld(lambda: issuer.request("/issue", changed))
    tamper_denied = withheld(
        lambda: executor.request("/execute", {"action": changed["action"], "grant": grant})
    )
    role_denied = withheld(
        lambda: issuer.request("/validate", {"action": task["action"], "grant": grant})
    )
    private_state_absent = not any(
        Path(path).exists()
        for path in (
            "/state/authority.db",
            "/state/effects.db",
            "/config/signing.seed",
            "/var/run/docker.sock",
        )
    )
    try:
        Path("/state/raw-agent-bypass.txt").write_text("HARMLESS_CANARY")
    except OSError:
        direct_write_denied = True
    else:
        direct_write_denied = False
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=1):
            external_egress_denied = False
    except OSError:
        external_egress_denied = True
    result = {
        "authorized_effect": True,
        "replay_without_dispatch": replay["replayed"],
        "unapproved_scope_denied": scope_denied,
        "changed_grant_denied": tamper_denied,
        "agent_cannot_validate_as_executor": role_denied,
        "issuer_and_executor_private_state_absent": private_state_absent,
        "direct_write_denied": direct_write_denied,
        "external_routed_egress_denied": external_egress_denied,
    }
    assert all(result.values()), result
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
