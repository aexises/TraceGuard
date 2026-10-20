"""Hardened Docker execution for argv-only command calls."""

from __future__ import annotations

import base64
import json
import os
import re
import selectors
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from traceguard.policy.authorization import sensitive_path
from traceguard.release_gate import ArtifactStore
from traceguard.sandbox.config import (
    ENABLED_PROFILES,
    InputLimits,
    SandboxProfile,
    load_sandbox_configuration,
)
from traceguard.tools.filesystem import CopyBudget, copy_confined, write_confined
from traceguard.types import ExecutionPlan, ExecutionTarget, SandboxEvidence

_Executor = Callable[..., subprocess.CompletedProcess[str]]
_ARCH_ALIASES = {"aarch64": "arm64", "x86_64": "amd64"}
_BLOCKED_PATTERNS = {
    "network": ("network is unreachable", "temporary failure in name resolution"),
    "filesystem": ("read-only file system", "permission denied"),
    "process_limit": ("resource temporarily unavailable", "cannot fork"),
}


class SandboxUnavailable(RuntimeError):
    """The sandbox cannot prove that execution is safely contained."""


class EvidenceCollectionError(SandboxUnavailable):
    """Bounded evidence or artifacts could not be collected safely."""


class ContainerRunner:
    """Execute a trusted plan using profiles loaded from a strict JSON file."""

    def __init__(
        self,
        config_path: Path,
        *,
        workspace_root: Path,
        artifact_root: Path,
        executor: _Executor = subprocess.run,
    ) -> None:
        try:
            self.config = load_sandbox_configuration(config_path.resolve())
        except ValueError as exc:
            raise SandboxUnavailable(str(exc)) from exc
        self.workspace_root = workspace_root.resolve()
        self.artifact_root = artifact_root.resolve()
        self.executor = executor

    @property
    def image(self) -> str:
        return self.config.image

    def check_environment(self) -> str:
        """Validate daemon architecture plus the local image's digest and architecture."""
        daemon = self._docker(
            ["docker", "version", "--format", "{{.Server.Arch}}"],
            timeout=10,
        )
        if daemon.returncode != 0:
            raise SandboxUnavailable("Docker daemon is unavailable")
        daemon_arch = _normalize_arch(daemon.stdout.strip())
        if daemon_arch not in self.config.allowed_architectures:
            raise SandboxUnavailable(f"Docker daemon architecture is not allowed: {daemon_arch}")

        inspected = self._docker(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Architecture}}|{{json .RepoDigests}}",
                self.image,
            ],
            timeout=10,
        )
        if inspected.returncode != 0:
            raise SandboxUnavailable("pinned sandbox image is unavailable locally")
        try:
            image_arch, repo_digests = inspected.stdout.strip().split("|", 1)
        except ValueError as exc:
            raise SandboxUnavailable("Docker returned malformed image metadata") from exc
        image_arch = _normalize_arch(image_arch)
        if image_arch != daemon_arch or image_arch not in self.config.allowed_architectures:
            raise SandboxUnavailable(
                f"sandbox image architecture {image_arch} does not match daemon {daemon_arch}"
            )
        expected_digest = self.image.rsplit("@", 1)[1]
        if expected_digest not in repo_digests:
            raise SandboxUnavailable("local image digest does not match trusted configuration")
        return image_arch

    def execute(self, plan: ExecutionPlan) -> SandboxEvidence:
        if plan.target is not ExecutionTarget.CONTAINER:
            raise ValueError("ContainerRunner requires a CONTAINER execution plan")
        if not plan.validated:
            raise SandboxUnavailable("container execution plan was not validated")
        profile = self._profile(plan.sandbox_profile)
        command = plan.effective_call.arguments.get("command")
        if (
            plan.effective_call.tool_name != "restricted_command"
            or not isinstance(command, list)
            or not command
            or not all(isinstance(part, str) and part for part in command)
        ):
            raise ValueError("restricted_command requires a non-empty argv list")

        self.check_environment()
        container_name = f"traceguard-{uuid4().hex}"
        started = time.monotonic()
        result: subprocess.CompletedProcess[str] | None = None
        timed_out = False
        timeout_stdout: str | bytes = ""
        timeout_stderr: str | bytes = ""
        resource_usage: dict[str, int] = {}
        monitor_stop = threading.Event()
        monitor: threading.Thread | None = None

        with tempfile.TemporaryDirectory(prefix="traceguard-sandbox-") as temporary:
            staging_root = Path(temporary).resolve()
            input_root = staging_root / "input"
            output_root = staging_root / "output"
            input_root.mkdir(mode=0o700)
            if profile.input_mode == "none":
                if plan.declared_input_paths:
                    raise SandboxUnavailable("isolated_compute does not accept host inputs")
            else:
                self._stage_inputs(plan.declared_input_paths, input_root, profile.input_limits)
            if profile.output_mode == "allowlisted":
                output_root.mkdir(mode=0o700)

            docker_command = self._build_command(
                container_name,
                command,
                profile,
                input_root=input_root,
                output_root=output_root,
            )
            if self.executor is subprocess.run:
                monitor = threading.Thread(
                    target=_monitor_resources,
                    args=(container_name, monitor_stop, resource_usage),
                    daemon=True,
                )
                monitor.start()
            try:
                if profile.output_mode == "allowlisted":
                    launch = self._docker(docker_command, timeout=10, output_limit=4096)
                    if launch.returncode != 0:
                        raise SandboxUnavailable("quota-backed output container could not start")
                    docker_command = ["docker", "exec", container_name, *command]
                result = self._docker(
                    docker_command,
                    timeout=profile.limits.timeout_seconds,
                    output_limit=profile.limits.output_bytes,
                )
                if profile.output_mode == "allowlisted":
                    self._collect_output(container_name, output_root, profile)
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                timeout_stdout = exc.stdout or ""
                timeout_stderr = exc.stderr or ""
            finally:
                monitor_stop.set()
                if monitor is not None:
                    monitor.join(timeout=3)
                self._cleanup_container(container_name)

            if profile.output_mode == "allowlisted":
                files_changed, artifact_bytes = self._inspect_artifacts(output_root, profile)
                artifact_directory = self._persist_artifacts(
                    output_root, files_changed, container_name
                )
            else:
                files_changed = []
                artifact_bytes = 0
                artifact_directory = None

        raw_stdout = timeout_stdout if timed_out else result.stdout if result else ""
        raw_stderr = timeout_stderr if timed_out else result.stderr if result else ""
        stdout, stdout_truncated = _bounded_text(raw_stdout, profile.limits.output_bytes)
        stderr, stderr_truncated = _bounded_text(raw_stderr, profile.limits.output_bytes)
        blocked = _blocked_operations(stderr)
        if timed_out:
            blocked.append("timeout")
        return SandboxEvidence(
            exit_code=None if timed_out else result.returncode if result else None,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            files_changed=files_changed,
            artifact_bytes=artifact_bytes,
            artifact_directory=artifact_directory,
            artifact_id=container_name if artifact_directory is not None else None,
            artifact_status="quarantined" if artifact_directory is not None else None,
            blocked_operations=blocked,
            duration_ms=(time.monotonic() - started) * 1000,
            peak_memory_bytes=resource_usage.get("peak_memory_bytes"),
            disk_usage_bytes=resource_usage.get("disk_usage_bytes"),
            timed_out=timed_out,
            profile=plan.sandbox_profile or "",
        )

    def _profile(self, name: str | None) -> SandboxProfile:
        if name not in ENABLED_PROFILES:
            raise SandboxUnavailable(f"unsupported or unsafe sandbox profile: {name}")
        profile = self.config.profiles[name]
        if not profile.enabled or profile.network != "none":
            raise SandboxUnavailable(f"sandbox profile is disabled or unsafe: {name}")
        return profile

    def _build_command(
        self,
        container_name: str,
        command: list[str],
        profile: SandboxProfile,
        *,
        input_root: Path,
        output_root: Path,
    ) -> list[str]:
        limits = profile.limits
        docker_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            self.config.container_user,
            "--pids-limit",
            str(limits.pids),
            "--memory",
            f"{limits.memory_mb}m",
            "--memory-swap",
            f"{limits.memory_mb}m",
            "--cpus",
            str(limits.cpu_count),
            "--ipc",
            "none",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={profile.tmpfs_mb}m",
            "--workdir",
            "/tmp" if profile.input_mode == "none" else "/traceguard/input",
            "--env",
            "HOME=/tmp",
        ]
        if profile.input_mode == "copy_readonly":
            docker_command.extend(
                [
                    "--mount",
                    f"type=bind,src={input_root},dst=/traceguard/input,readonly",
                ]
            )
        if profile.output_mode == "allowlisted":
            uid, gid = self.config.container_user.split(":")
            docker_command.extend(
                [
                    "--detach",
                    "--tmpfs",
                    "/traceguard/output:rw,noexec,nosuid,nodev,"
                    f"size={profile.artifact_limits.max_total_bytes},"
                    f"nr_inodes={profile.artifact_limits.max_inodes},uid={uid},gid={gid},mode=0700",
                    "--env",
                    "TRACEGUARD_OUTPUT=/traceguard/output",
                ]
            )
            # Keep tmpfs mounted for bounded export; forced cleanup terminates all children.
            return [
                *docker_command,
                self.image,
                "python3",
                "-I",
                "-c",
                f"import time; time.sleep({profile.limits.timeout_seconds + 30})",
            ]
        return [*docker_command, self.image, *command]

    def _collect_output(self, container: str, output_root: Path, profile: SandboxProfile) -> None:
        script = (Path(__file__).parents[1] / "data/sandbox/export.py").read_text()
        limits = profile.artifact_limits
        max_export = limits.max_total_bytes * 2 + limits.max_entries * 4096 + 65_536
        result = self._docker(
            [
                "docker",
                "exec",
                container,
                "python3",
                "-I",
                "-c",
                script,
                "/traceguard/output",
                limits.model_dump_json(),
            ],
            timeout=10,
            output_limit=max_export,
        )
        if result.returncode != 0 or len(result.stdout.encode()) > max_export:
            raise EvidenceCollectionError("artifact export failed or exceeded its budget")
        try:
            files = json.loads(result.stdout)
            if not isinstance(files, list) or len(files) > limits.max_files:
                raise ValueError("invalid exported file count")
            total, paths = 0, set()
            for item in files:
                relative = item["path"]
                if relative in paths or len(Path(relative).parts) > limits.max_depth:
                    raise ValueError("duplicate or excessively nested artifact")
                paths.add(relative)
                data = base64.b64decode(item["data"], validate=True)
                total += len(data)
                if len(data) > limits.max_file_bytes or total > limits.max_total_bytes:
                    raise ValueError("exported artifact exceeds size budget")
                write_confined(output_root, relative, data)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            raise EvidenceCollectionError("untrusted artifact export is invalid") from exc

    def _stage_inputs(
        self, declared_paths: list[str], input_root: Path, limits: InputLimits | None = None
    ) -> None:
        budget = CopyBudget(**(limits or InputLimits()).model_dump())
        for raw_path in declared_paths:
            relative = Path(raw_path)
            if relative.is_absolute() or ".." in relative.parts or relative == Path("."):
                raise SandboxUnavailable(f"declared input is outside the workspace: {raw_path}")
            if sensitive_path(raw_path):
                raise SandboxUnavailable("protected declared input is not allowed")
            destination = input_root / relative
            if destination.exists():
                raise SandboxUnavailable(f"overlapping declared input: {raw_path}")
            try:
                copy_confined(
                    self.workspace_root,
                    raw_path,
                    destination,
                    budget=budget,
                    prohibited=sensitive_path,
                )
            except (ValueError, OSError) as exc:
                raise SandboxUnavailable(
                    "unsafe symbolic-link/aliased/protected input or staging limit exceeded"
                ) from exc
        _make_tree_readonly(input_root)

    @staticmethod
    def _inspect_artifacts(output_root: Path, profile: SandboxProfile) -> tuple[list[str], int]:
        changed: list[str] = []
        total = 0
        try:
            paths = output_root.rglob("*")
            entries = 0
            for path in paths:
                entries += 1
                if entries > profile.artifact_limits.max_entries:
                    raise EvidenceCollectionError("artifact entry limit exceeded")
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise EvidenceCollectionError("artifact symbolic links are not allowed")
                if path.is_dir():
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise EvidenceCollectionError("artifact is not a regular file")
                relative = path.relative_to(output_root).as_posix()
                if metadata.st_size > profile.artifact_limits.max_file_bytes:
                    raise EvidenceCollectionError(f"artifact exceeds per-file limit: {relative}")
                changed.append(relative)
                total += metadata.st_size
                if len(changed) > profile.artifact_limits.max_files:
                    raise EvidenceCollectionError("artifact file-count limit exceeded")
                if total > profile.artifact_limits.max_total_bytes:
                    raise EvidenceCollectionError("artifact total-size limit exceeded")
        except OSError as exc:
            raise EvidenceCollectionError("artifact inspection failed") from exc
        return changed, total

    def _persist_artifacts(
        self, output_root: Path, files_changed: list[str], container_name: str
    ) -> str | None:
        if not files_changed:
            return None
        try:
            store = ArtifactStore(self.artifact_root)
            identity = store.ingest(output_root, files_changed, artifact_id=container_name)
        except (OSError, ValueError) as exc:
            raise EvidenceCollectionError("artifact persistence failed") from exc
        return str(store.private / identity / "files")

    def reject_artifacts(self, evidence: SandboxEvidence) -> None:
        if evidence.artifact_id:
            ArtifactStore(self.artifact_root).reject(evidence.artifact_id)

    def _cleanup_container(self, container_name: str) -> None:
        try:
            result = self._docker(["docker", "rm", "--force", container_name], timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            raise EvidenceCollectionError("container cleanup could not be verified") from exc
        if result.returncode != 0 and "no such container" not in result.stderr.casefold():
            raise EvidenceCollectionError("container cleanup could not be verified")

    def _docker(
        self,
        command: list[str],
        *,
        timeout: int | float,
        output_limit: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            if self.executor is subprocess.run and output_limit is not None:
                return _run_bounded_command(command, timeout=timeout, limit=output_limit)
            return self.executor(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise SandboxUnavailable("Docker CLI is unavailable") from exc


def _normalize_arch(value: str) -> str:
    return _ARCH_ALIASES.get(value, value)


def _bounded_text(value: str | bytes, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace") if isinstance(value, str) else value
    truncated = len(encoded) > limit
    return encoded[:limit].decode("utf-8", errors="replace"), truncated


def _blocked_operations(stderr: str) -> list[str]:
    lowered = stderr.casefold()
    return [
        operation
        for operation, patterns in _BLOCKED_PATTERNS.items()
        if any(pattern in lowered for pattern in patterns)
    ]


def _make_tree_readonly(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def _run_bounded_command(
    command: list[str], *, timeout: int | float, limit: int
) -> subprocess.CompletedProcess[str]:
    """Drain both output pipes while retaining at most limit + 1 bytes each."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None
    assert process.stderr is not None
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise subprocess.TimeoutExpired(
                    command,
                    timeout,
                    output=bytes(streams[process.stdout]).decode("utf-8", errors="replace"),
                    stderr=bytes(streams[process.stderr]).decode("utf-8", errors="replace"),
                )
            for key, _ in selector.select(min(remaining, 0.1)):
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                retained = streams[stream]
                if len(retained) <= limit:
                    retained.extend(chunk[: limit + 1 - len(retained)])
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(
        command,
        returncode,
        bytes(streams[process.stdout]).decode("utf-8", errors="replace"),
        bytes(streams[process.stderr]).decode("utf-8", errors="replace"),
    )


def _monitor_resources(
    container_name: str,
    stop: threading.Event,
    measurements: dict[str, int],
) -> None:
    """Sample bounded Docker resource metadata while the named container exists."""
    while not stop.is_set():
        try:
            stats = subprocess.run(
                [
                    "docker",
                    "stats",
                    "--no-stream",
                    "--format",
                    "{{.MemUsage}}",
                    container_name,
                ],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if stats.returncode == 0:
                usage = stats.stdout.partition("/")[0].strip()
                memory = _parse_docker_bytes(usage)
                if memory is not None:
                    measurements["peak_memory_bytes"] = max(
                        memory, measurements.get("peak_memory_bytes", 0)
                    )
            disk = subprocess.run(
                [
                    "docker",
                    "container",
                    "inspect",
                    "--size",
                    "--format",
                    "{{.SizeRw}}",
                    container_name,
                ],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if disk.returncode == 0:
                measurements["disk_usage_bytes"] = max(
                    int(disk.stdout.strip()),
                    measurements.get("disk_usage_bytes", 0),
                )
        except (FileNotFoundError, subprocess.SubprocessError, ValueError):
            pass
        stop.wait(0.02)


def _parse_docker_bytes(value: str) -> int | None:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?i?b)", value.casefold())
    if match is None:
        return None
    amount = float(match.group(1))
    factors = {
        "b": 1,
        "kb": 1_000,
        "kib": 1_024,
        "mb": 1_000_000,
        "mib": 1_048_576,
        "gb": 1_000_000_000,
        "gib": 1_073_741_824,
        "tb": 1_000_000_000_000,
        "tib": 1_099_511_627_776,
    }
    return int(amount * factors[match.group(2)])
