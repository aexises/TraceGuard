"""Explicit data release and private artifact quarantine for supported integrations."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from uuid import uuid4

from traceguard.limits import validate_json
from traceguard.supervisor.redaction import redact_value
from traceguard.tools.filesystem import CopyBudget, copy_confined, read_confined, write_confined


def _locked(method):
    @wraps(method)
    def transaction(self, *args, **kwargs):
        descriptor = os.open(self.private / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return method(self, *args, **kwargs)
        finally:
            os.close(descriptor)

    return transaction


@dataclass(frozen=True)
class ReleaseGate:
    allowed_sinks: frozenset[str]
    allowed_labels: frozenset[str] = frozenset({"public"})
    prohibited_literals: tuple[str, ...] = ()
    max_bytes: int = 1_048_576
    artifact_suffixes: frozenset[str] = frozenset({".txt", ".json"})

    def __post_init__(self):
        object.__setattr__(self, "allowed_sinks", frozenset(self.allowed_sinks))
        object.__setattr__(self, "allowed_labels", frozenset(self.allowed_labels))
        object.__setattr__(self, "prohibited_literals", tuple(self.prohibited_literals))
        object.__setattr__(self, "artifact_suffixes", frozenset(self.artifact_suffixes))
        if not 0 < self.max_bytes <= 16_777_216:
            raise ValueError("release byte budget must be within sixteen MiB")

    def authorize(self, sink: str, content: bytes, *, label: str = "unclassified") -> bytes:
        """Labels and sink permissions must come from trusted application configuration."""
        if sink not in self.allowed_sinks or label not in self.allowed_labels:
            raise PermissionError("data classification is not approved for this release sink")
        if len(content) > self.max_bytes:
            raise PermissionError("release exceeds byte budget")
        text = content.decode("utf-8", errors="strict")
        if any(value and value in text for value in self.prohibited_literals):
            raise PermissionError("release contains explicitly protected content")
        try:
            structured = json.loads(text)
        except ValueError:
            structured = text
        try:
            validate_json(structured, max_bytes=self.max_bytes, max_nodes=16_384, max_depth=32)
        except ValueError as exc:
            raise PermissionError("release structure exceeds budget") from exc
        normalized = json.dumps(structured, ensure_ascii=False)
        if any(value and value in normalized for value in self.prohibited_literals):
            raise PermissionError("release contains explicitly protected content")
        if redact_value(structured) != structured:
            raise PermissionError("release contains recognized credentials")
        return content


class GuardedProvider:
    """Apply release policy before invoking a model provider, including post-run calls."""

    def __init__(self, provider, gate: ReleaseGate, *, input_label: str = "unclassified"):
        self.provider, self.gate, self.input_label = provider, gate, input_label

    def evaluate(self, request):
        self.gate.authorize(
            "model_provider", request.model_dump_json().encode(), label=self.input_label
        )
        return self.provider.evaluate(request)

    def evaluate_post_run(self, request):
        self.gate.authorize(
            "model_provider", request.model_dump_json().encode(), label=self.input_label
        )
        return self.provider.evaluate_post_run(request)


class ArtifactStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.private = self.root / "quarantine"
        self.released = self.root / "released"
        self.private.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.private.chmod(0o700)
        self.released.mkdir(parents=True, exist_ok=True, mode=0o700)

    @staticmethod
    def _id(artifact_id: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9-]{1,80}", artifact_id):
            raise ValueError("invalid artifact identity")
        return artifact_id

    def ingest(self, source: Path, paths: list[str], *, artifact_id: str | None = None) -> str:
        identity = self._id(artifact_id or uuid4().hex)
        directory = self.private / identity
        directory.mkdir(mode=0o700)
        content_root = directory / "files"
        content_root.mkdir(mode=0o700)
        records = {}
        budget = CopyBudget()
        try:
            for path in paths:
                copy_confined(source, path, content_root / path, budget=budget)
                records[path] = hashlib.sha256(
                    read_confined(content_root, path, max_bytes=budget.max_file_bytes)
                ).hexdigest()
            manifest = {"id": identity, "status": "quarantined", "files": records}
            write_confined(
                directory, "manifest.json", json.dumps(manifest, sort_keys=True).encode()
            )
        except BaseException:
            shutil.rmtree(directory, ignore_errors=True)
            raise
        return identity

    def manifest(self, artifact_id: str) -> dict:
        return json.loads(
            read_confined(
                self.private / self._id(artifact_id), "manifest.json", max_bytes=1_048_576
            )
        )

    @_locked
    def reject(self, artifact_id: str) -> None:
        manifest = self.manifest(artifact_id)
        if manifest["status"] != "quarantined":
            raise ValueError("artifact is not quarantined")
        manifest["status"] = "rejected"
        write_confined(self.private / artifact_id, "manifest.json", json.dumps(manifest).encode())

    @_locked
    def release(self, artifact_id: str, gate: ReleaseGate, *, label: str = "unclassified") -> Path:
        identity = self._id(artifact_id)
        manifest = self.manifest(identity)
        if manifest["status"] != "quarantined":
            raise PermissionError("artifact is not eligible for release")
        pending = self.released / (".pending-" + uuid4().hex)
        pending.mkdir(mode=0o700)
        try:
            total = 0
            for path, expected in manifest["files"].items():
                if Path(path).suffix.casefold() not in gate.artifact_suffixes:
                    raise PermissionError("artifact format is not approved for this sink")
                data = read_confined(
                    self.private / identity / "files", path, max_bytes=gate.max_bytes
                )
                total += len(data)
                if total > gate.max_bytes or hashlib.sha256(data).hexdigest() != expected:
                    raise PermissionError("artifact changed or exceeds release budget")
                gate.authorize("artifact", data, label=label)
                write_confined(pending, path, data)
            destination = self.released / identity
            if destination.exists():
                raise ValueError("artifact release already exists")
            pending.rename(destination)
            manifest["status"] = "released"
            write_confined(self.private / identity, "manifest.json", json.dumps(manifest).encode())
            return destination
        finally:
            shutil.rmtree(pending, ignore_errors=True)
