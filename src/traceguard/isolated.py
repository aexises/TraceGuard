"""Narrow isolated report executor: mTLS identity, online grants, private output authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from traceguard.control.execution import ExecutionAuthority
from traceguard.control.models import Actor, GrantRequest, GrantValidation
from traceguard.control.service import AuthorizationError, action_digest
from traceguard.control.storage import SQLiteControlPlane
from traceguard.executor import MediatedExecutor, ProviderReceipt
from traceguard.mtls import BoundaryServer, MTLSClient, PeerIdentities, tls_context
from traceguard.release_gate import ArtifactStore, ReleaseGate
from traceguard.tools.filesystem import read_confined, write_confined


def adapter_digest() -> str:
    """Bind the deployed Python code and reviewed effect descriptors, not a request claim."""
    root = Path(__file__).parent
    digest = hashlib.sha256()
    paths = sorted(root.rglob("*.py")) + [
        root / "data/policy/effects.json",
        root / "data/policy/security_effects.json",
    ]
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


class ReportAdapter:
    def __init__(self, state: Path, gate: ReleaseGate):
        self.state, self.gate = state.resolve(), gate
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store = ArtifactStore(self.state / "artifacts")

    def dispatch(self, action) -> str:
        if action.operation != "write_report" or action.target is not None:
            raise AuthorizationError("unsupported report adapter operation or target")
        identity = hashlib.sha256(
            (action.tenant_id + "\0" + action.task_id + "\0" + action.idempotency_key).encode()
        ).hexdigest()
        directory = self.store.private / identity
        if not directory.exists():
            with tempfile.TemporaryDirectory(dir=self.state) as temporary:
                source = Path(temporary).resolve()
                path = action.arguments["path"]
                write_confined(source, path, action.arguments["content"].encode())
                self.store.ingest(
                    source, [path], artifact_id=identity, action_digest=action_digest(action)
                )
            self.store.release(identity, self.gate, label="public")
        manifest = self.store.manifest(identity)
        if (
            manifest.get("action_digest") != action_digest(action)
            or manifest["status"] != "released"
        ):
            raise AuthorizationError("provider receipt is inconsistent or uncertain")
        return json.dumps(
            {"status": "released", "artifact_id": identity, "action_digest": action_digest(action)}
        )

    def reconcile(self, record: dict, reference: str) -> ProviderReceipt:
        manifest = self.store.manifest(reference)
        if manifest["status"] != "released" or manifest.get("action_digest") != record["digest"]:
            raise AuthorizationError("no definitive matching provider receipt")
        for path, expected in manifest["files"].items():
            content = read_confined(
                self.store.released / reference, path, max_bytes=self.gate.max_bytes
            )
            if hashlib.sha256(content).hexdigest() != expected:
                raise AuthorizationError("provider effect integrity failed")
        return ProviderReceipt(
            record["digest"],
            reference,
            "succeeded",
            json.dumps(
                {
                    "status": "released",
                    "artifact_id": reference,
                    "action_digest": record["digest"],
                }
            ),
        )


class AuthorityService:
    def __init__(self, config: dict):
        root, state = Path(config["identity_directory"]), Path(config["state_directory"])
        self.control = SQLiteControlPlane(
            state / "authority.db", read_confined(root, "signing.seed", max_bytes=32)
        )
        self.issuer = ExecutionAuthority(self.control)

    def __call__(self, actor: Actor, path: str, payload: dict) -> dict:
        if path == "/issue":
            request = GrantRequest.model_validate(payload)
            return self.issuer.issue(
                actor, request.action, request.executor_audience, request.review_id
            ).model_dump(mode="json")
        if path == "/validate":
            request = GrantValidation.model_validate(payload)
            self.issuer.validate(actor, request.action, request.grant)
            return {"valid": True}
        raise AuthorizationError("unsupported authority operation")


class ExecutorService:
    def __init__(self, config: dict):
        root, state = Path(config["identity_directory"]), Path(config["state_directory"])
        if adapter_digest() != config["adapter_digest"]:
            raise ValueError("deployed adapter artifact does not match approved code")
        client = MTLSClient(
            config["issuer_url"],
            tls_context(root / "certificate.pem", root / "key.pem", root / "ca.pem"),
            config["issuer_fingerprint"],
        )

        def validate(identity, action, grant):
            result = client.request(
                "/validate",
                {"action": action.model_dump(mode="json"), "grant": grant.model_dump(mode="json")},
            )
            if result != {"valid": True}:
                raise AuthorizationError("issuer did not affirm current execution authority")

        gate = ReleaseGate(
            frozenset({"artifact"}),
            allowed_labels=frozenset({"public"}),
            prohibited_literals=tuple(config.get("protected_literals", ())),
        )
        self.adapter = ReportAdapter(state, gate)
        self.executor = MediatedExecutor(
            state / "effects.db",
            identity=Actor.model_validate(config["identity"]),
            public_key=bytes.fromhex(config["issuer_public_key"]),
            key_id=config["issuer_key_id"],
            adapter_digest=config["adapter_digest"],
            validate_online=validate,
            dispatch=self.adapter.dispatch,
            reconcile_provider=self.adapter.reconcile,
        )

    def __call__(self, actor: Actor, path: str, payload: dict) -> dict:
        if path != "/execute":
            raise AuthorizationError("unsupported executor operation")
        request = GrantValidation.model_validate(payload)
        if request.action.operation != "write_report" or request.action.target is not None:
            raise AuthorizationError("unsupported adapter action")
        return self.executor.execute(actor, request.action, request.grant)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_bytes())
    root = Path(config["identity_directory"])
    services = {"authority": AuthorityService, "executor": ExecutorService}
    service = services[config["role"]](config)
    server = BoundaryServer(
        (config.get("host", "0.0.0.0"), config.get("port", 9443)),
        context=tls_context(
            root / "certificate.pem", root / "key.pem", root / "ca.pem", server=True
        ),
        identities=PeerIdentities(root / "peers.json"),
        dispatch=service,
    )
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
