"""Explicit data release and private artifact quarantine for supported integrations."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from uuid import uuid4

from traceguard.control.signing import canonical
from traceguard.limits import validate_json
from traceguard.supervisor.redaction import redact_value
from traceguard.tools.filesystem import CopyBudget, copy_confined, read_confined, write_confined

COMMIT_MANIFEST = ".traceguard-commit.json"


class AlreadyPublished(RuntimeError):
    """The bundle is committed; rejecting an unpublished artifact is no longer possible."""


class PublicationUnknown(RuntimeError):
    """Visible publication state needs recovery; never infer that nothing was released."""


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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

    def ingest(
        self,
        source: Path,
        paths: list[str],
        *,
        artifact_id: str | None = None,
        action_digest: str | None = None,
    ) -> str:
        identity = self._id(artifact_id or uuid4().hex)
        directory = self.private / identity
        directory.mkdir(mode=0o700)
        content_root = directory / "files"
        content_root.mkdir(mode=0o700)
        records = {}
        budget = CopyBudget()
        try:
            for path in paths:
                if not Path(path).parts or Path(path).parts[0] == COMMIT_MANIFEST:
                    raise ValueError("artifact uses reserved publication metadata path")
                copy_confined(source, path, content_root / path, budget=budget)
                records[path] = hashlib.sha256(
                    read_confined(content_root, path, max_bytes=budget.max_file_bytes)
                ).hexdigest()
            manifest = {"id": identity, "status": "quarantined", "files": records}
            if action_digest is not None:
                if not re.fullmatch(r"[0-9a-f]{64}", action_digest):
                    raise ValueError("invalid action binding")
                manifest["action_digest"] = action_digest
            write_confined(
                directory, "manifest.json", json.dumps(manifest, sort_keys=True).encode()
            )
        except BaseException:
            shutil.rmtree(directory, ignore_errors=True)
            raise
        return identity

    def manifest(self, artifact_id: str) -> dict:
        identity = self._id(artifact_id)
        destination = self.released / identity
        if destination.exists() or destination.is_symlink():
            return self.committed(identity)
        manifest = json.loads(
            read_confined(
                self.private / self._id(artifact_id), "manifest.json", max_bytes=1_048_576
            )
        )
        if manifest.get("status") == "released":
            raise PublicationUnknown(
                "private mirror claims publication but committed bundle is absent"
            )
        return manifest

    def committed(self, artifact_id: str, *, ensure_durable: bool = False) -> dict:
        """Consumers/reconciliation must verify this self-contained authoritative bundle."""
        identity = self._id(artifact_id)
        directory = self.released / identity
        try:
            manifest = json.loads(read_confined(directory, COMMIT_MANIFEST, max_bytes=1_048_576))
            validate_json(manifest, max_bytes=1_048_576, max_nodes=16_384, max_depth=32)
            if not isinstance(manifest, dict):
                raise ValueError("invalid commit manifest")
            if (
                manifest.get("schema") != 1
                or manifest.get("id") != identity
                or manifest.get("status") != "released"
                or manifest.get("sink") != "artifact"
                or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("policy_digest", ""))
                or not isinstance(manifest.get("files"), dict)
                or len(manifest["files"]) > 1024
            ):
                raise ValueError("invalid commit manifest")
            total = 0
            actual = set()
            for count, path in enumerate(directory.rglob("*"), 1):
                mode = path.lstat().st_mode
                if count > 2048 or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise ValueError("invalid publication tree")
                if stat.S_ISREG(mode):
                    actual.add(path.relative_to(directory).as_posix())
            if actual != set(manifest["files"]) | {COMMIT_MANIFEST}:
                raise ValueError("publication file set differs from commit")
            for path, expected in manifest["files"].items():
                data = read_confined(directory, path, max_bytes=16_777_216)
                total += len(data)
                if total > 16_777_216 or hashlib.sha256(data).hexdigest() != expected:
                    raise ValueError("published artifact integrity failed")
            if ensure_durable:
                _sync_directory(self.released)
                _sync_directory(self.private)
            return manifest
        except (OSError, ValueError, TypeError) as exc:
            raise PublicationUnknown(
                "publication is missing, corrupt or requires migration"
            ) from exc

    @_locked
    def reject(self, artifact_id: str) -> None:
        destination = self.released / self._id(artifact_id)
        if destination.exists() or destination.is_symlink():
            self.committed(artifact_id)
            raise AlreadyPublished("artifact already published; rejection cannot withdraw it")
        manifest = self.manifest(artifact_id)
        if manifest["status"] != "quarantined":
            raise ValueError("artifact is not quarantined")
        manifest["status"] = "rejected"
        write_confined(self.private / artifact_id, "manifest.json", json.dumps(manifest).encode())

    @_locked
    def release(self, artifact_id: str, gate: ReleaseGate, *, label: str = "unclassified") -> Path:
        identity = self._id(artifact_id)
        destination = self.released / identity
        if destination.exists() or destination.is_symlink():
            self.committed(identity, ensure_durable=True)
            return destination
        manifest = self.manifest(identity)
        if manifest["status"] != "quarantined":
            raise PermissionError("artifact is not eligible for release")
        pending = self.private / (".publication-" + uuid4().hex)
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
            commit = {
                **manifest,
                "schema": 1,
                "status": "released",
                "sink": "artifact",
                "label": label,
                "policy_digest": hashlib.sha256(
                    canonical(
                        {
                            "allowed_sinks": sorted(gate.allowed_sinks),
                            "allowed_labels": sorted(gate.allowed_labels),
                            "prohibited_literals": gate.prohibited_literals,
                            "max_bytes": gate.max_bytes,
                            "artifact_suffixes": sorted(gate.artifact_suffixes),
                        }
                    )
                ).hexdigest(),
            }
            validate_json(commit, max_bytes=1_048_576, max_nodes=16_384, max_depth=32)
            write_confined(pending, COMMIT_MANIFEST, canonical(commit))
            for directory in sorted(
                (path for path in pending.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            ):
                _sync_directory(directory)
            _sync_directory(pending)
            if pending.stat().st_dev != self.released.stat().st_dev:
                raise ValueError("atomic publication requires one supported local filesystem")
            if destination.exists() or destination.is_symlink():
                raise ValueError("artifact release already exists")
            try:
                pending.rename(destination)
            except OSError as exc:
                if destination.exists() or not pending.exists():
                    raise PublicationUnknown(
                        "publication rename outcome requires recovery"
                    ) from exc
                raise
            try:
                _sync_directory(self.released)
                _sync_directory(self.private)
            except OSError as exc:
                raise PublicationUnknown(
                    "bundle visible; directory durability requires recovery"
                ) from exc
            try:
                write_confined(self.private / identity, "manifest.json", canonical(commit))
            except OSError:
                pass  # The public commit is authoritative; this private mirror is recoverable.
            return destination
        finally:
            shutil.rmtree(pending, ignore_errors=True)

    @_locked
    def quarantine_legacy_publications(self, *, workers_and_consumers_fenced: bool) -> list[str]:
        if not workers_and_consumers_fenced:
            raise ValueError("fence publishers and consumers before legacy migration")
        moved = []
        for directory in self.released.iterdir():
            try:
                self.committed(directory.name)
            except (ValueError, PublicationUnknown):
                directory.rename(self.private / ("legacy-publication-" + uuid4().hex))
                moved.append(directory.name)
        _sync_directory(self.private)
        _sync_directory(self.released)
        return moved
