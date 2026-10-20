"""Generate disposable PKI and an approved report task for isolation conformance only."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from traceguard.control.execution import ExecutionAuthority
from traceguard.control.models import (
    Actor,
    PolicyDraft,
    PolicyRule,
    Role,
    RuleMatch,
    TaskRegistration,
)
from traceguard.control.storage import SQLiteControlPlane
from traceguard.isolated import adapter_digest
from traceguard.ledger import ExecutionLedger
from traceguard.types import TaskAuthority


def prepare(root: Path, *, container_paths: bool = False) -> dict:
    """No real credentials/providers; the private fixture CA key is never written."""
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TraceGuard disposable test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    fingerprints, directories = {}, {}
    for role in ["authority", "executor", "agent", "unknown"]:
        directory = root / role
        directory.mkdir(mode=0o700)
        directories[role] = directory
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(role), x509.DNSName("localhost")]), False
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                    if role == "executor"
                    else [ExtendedKeyUsageOID.SERVER_AUTH]
                    if role == "authority"
                    else [ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(ca_key, hashes.SHA256())
        )
        (directory / "certificate.pem").write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )
        (directory / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (directory / "key.pem").chmod(0o600)
        (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        fingerprints[role] = certificate.fingerprint(hashes.SHA256()).hex()
    agent = Actor(
        subject="agent",
        roles={Role.AGENT},
        service_key_id=fingerprints["agent"],
        tenant_ids={"tenant"},
        allowed_operations={"write_report"},
    )
    executor = Actor(
        subject="executor",
        roles={Role.EXECUTOR},
        service_key_id=fingerprints["executor"],
        tenant_ids={"tenant"},
    )
    peers = {
        fingerprints["agent"]: agent.model_dump(mode="json"),
        fingerprints["executor"]: executor.model_dump(mode="json"),
    }
    for role in ["authority", "executor"]:
        (directories[role] / "peers.json").write_text(json.dumps(peers))
    seed = secrets.token_bytes(32)
    (directories["authority"] / "signing.seed").write_bytes(seed)
    (directories["authority"] / "signing.seed").chmod(0o600)
    state = root / "authority-state"
    state.mkdir(mode=0o700)
    plane = SQLiteControlPlane(state / "authority.db", seed, initialize=True)
    author = Actor(subject="fixture-author", roles={Role.ADMIN}, tenant_ids={"tenant"})
    approver = Actor(subject="fixture-approver", roles={Role.APPROVER}, tenant_ids={"tenant"})
    draft = plane.create_draft(
        "tenant",
        author,
        PolicyDraft(
            name="approved report",
            rules=[
                PolicyRule(
                    name="report",
                    priority=1,
                    match=RuleMatch(kind="tool", operation="write_report"),
                    decision="ALLOW",
                    reason="disposable isolation conformance",
                )
            ],
        ),
    )
    plane.submit_policy("tenant", author, draft.policy_id)
    plane.approve_policy("tenant", approver, draft.policy_id)
    issuer = ExecutionAuthority(plane)
    digest = adapter_digest()
    executor_state = root / "executor-state"
    execution_domain = ExecutionLedger.provision(executor_state / "effects.db")
    authority = TaskAuthority(
        enforcement_mode="strict",
        allowed_tools=["write_report"],
        argument_values={"write_report": {"path": "reports/report.txt"}},
        generated_fields={"write_report": ["content"]},
    )
    issuer.register(
        "tenant",
        author,
        TaskRegistration(
            task_id="approved-task",
            agent_subject=agent.subject,
            service_key_id=agent.service_key_id,
            execution_domain=execution_domain,
            authority=authority.model_dump(mode="json"),
            adapter_digest=digest,
            tool_schemas={
                "write_report": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string", "maxLength": 32768},
                    },
                    "required": ["path", "content"],
                    "additionalProperties": False,
                }
            },
        ),
    )
    configs = {}
    for role in ["authority", "executor"]:
        state_dir = root / f"{role}-state"
        state_dir.mkdir(mode=0o700, exist_ok=True)
        config = {
            "role": role,
            "identity_directory": "/config" if container_paths else str(directories[role]),
            "state_directory": "/state" if container_paths else str(state_dir),
        }
        if role == "executor":
            config.update(
                identity=executor.model_dump(mode="json"),
                adapter_digest=digest,
                execution_domain=execution_domain,
                issuer_url="https://authority:9443",
                issuer_fingerprint=fingerprints["authority"],
                issuer_public_key=issuer.public_key.hex(),
                issuer_key_id=issuer.key_id,
                protected_literals=["DECLARED_PRIVATE_CANARY"],
            )
        (directories[role] / "config.json").write_text(json.dumps(config))
        configs[role] = config
    task = {
        "action": {
            "tenant_id": "tenant",
            "task_id": "approved-task",
            "idempotency_key": "approved-report-key",
            "kind": "tool",
            "operation": "write_report",
            "arguments": {"path": "reports/report.txt", "content": "Approved public report"},
        },
        "executor_audience": "executor",
    }
    (directories["agent"] / "task.json").write_text(json.dumps(task))
    (directories["agent"] / "services.json").write_text(
        json.dumps(
            {
                "authority": fingerprints["authority"],
                "executor": fingerprints["executor"],
            }
        )
    )
    return {
        "directories": directories,
        "configs": configs,
        "fingerprints": fingerprints,
        "task": task,
        "agent": agent,
        "executor": executor,
    }
