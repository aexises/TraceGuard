import json
import subprocess
import sys
from pathlib import Path

import pytest

from traceguard.sandbox.config import load_sandbox_configuration
from traceguard.sandbox.runner import (
    ContainerRunner,
    EvidenceCollectionError,
    SandboxUnavailable,
    _parse_docker_bytes,
    _run_bounded_command,
)
from traceguard.types import ExecutionPlan, ExecutionTarget, SandboxLimits, ToolCall

CONFIG_PATH = Path(__file__).parents[2] / "configs" / "sandbox_profiles.json"


def plan(
    profile: str = "isolated_compute",
    *,
    inputs: list[str] | None = None,
    command: list[str] | None = None,
    validated: bool = True,
) -> ExecutionPlan:
    call = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="restricted_command",
        arguments={"command": command or ["python3", "-V"]},
    )
    return ExecutionPlan(
        effective_call=call,
        target=ExecutionTarget.CONTAINER,
        sandbox_profile=profile,
        declared_input_paths=inputs or [],
        validated=validated,
    )


class FakeDocker:
    def __init__(
        self,
        *,
        run_stdout: str = "ok",
        run_stderr: str = "",
        architecture: str = "arm64",
        digest_matches: bool = True,
        run_returncode: int = 0,
    ) -> None:
        self.commands: list[list[str]] = []
        self.run_stdout = run_stdout
        self.run_stderr = run_stderr
        self.architecture = architecture
        self.digest_matches = digest_matches
        self.run_returncode = run_returncode
        self.on_run = None

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[1] == "version":
            return subprocess.CompletedProcess(command, 0, self.architecture, "")
        if command[1:3] == ["image", "inspect"]:
            digest = "sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4"
            if not self.digest_matches:
                digest = "sha256:" + "0" * 64
            return subprocess.CompletedProcess(
                command,
                0,
                f'{self.architecture}|["python@{digest}"]',
                "",
            )
        if command[1] == "run":
            if self.on_run:
                self.on_run(command)
            return subprocess.CompletedProcess(
                command,
                self.run_returncode,
                self.run_stdout,
                self.run_stderr,
            )
        if command[1:3] == ["rm", "--force"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected Docker command: {command}")


def runner(tmp_path: Path, fake: FakeDocker) -> ContainerRunner:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return ContainerRunner(
        CONFIG_PATH,
        workspace_root=workspace,
        artifact_root=tmp_path / "artifacts",
        executor=fake,
    )


def docker_run(fake: FakeDocker) -> list[str]:
    return next(command for command in fake.commands if command[1] == "run")


def mount_source(command: list[str], destination: str) -> Path:
    mount = next(
        command[index + 1]
        for index, value in enumerate(command)
        if value == "--mount" and f"dst={destination}" in command[index + 1]
    )
    source = next(part.removeprefix("src=") for part in mount.split(",") if part.startswith("src="))
    return Path(source)


def test_trusted_configuration_is_strict_and_network_profile_is_disabled(tmp_path):
    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    assert load_sandbox_configuration(CONFIG_PATH).profiles["restricted_network"].enabled is False

    raw["profiles"]["restricted_network"]["enabled"] = True
    unsafe = tmp_path / "unsafe.json"
    unsafe.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="restricted_network"):
        load_sandbox_configuration(unsafe)

    raw["profiles"]["restricted_network"]["enabled"] = False
    raw["agent_docker_flags"] = ["--privileged"]
    unsafe.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="Extra inputs"):
        load_sandbox_configuration(unsafe)


def test_rejects_unpinned_image_in_configuration(tmp_path):
    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    raw["image"] = "python:3.11-alpine"
    config = tmp_path / "untrusted.json"
    config.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(SandboxUnavailable, match="immutable sha256"):
        ContainerRunner(
            config,
            workspace_root=tmp_path,
            artifact_root=tmp_path / "artifacts",
        )


def test_builds_hardened_no_network_command_from_trusted_limits(tmp_path):
    fake = FakeDocker()
    malicious_limits = SandboxLimits(
        timeout_seconds=300,
        memory_mb=4096,
        cpu_count=4,
        pids=512,
        output_bytes=1048576,
    )
    execution_plan = plan()
    execution_plan.limits = malicious_limits
    evidence = runner(tmp_path, fake).execute(execution_plan)

    command = docker_run(fake)
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--user") + 1] == "65532:65532"
    assert command[command.index("--pids-limit") + 1] == "64"
    assert command[command.index("--memory") + 1] == "256m"
    assert command[command.index("--memory-swap") + 1] == "256m"
    assert command[command.index("--cpus") + 1] == "1.0"
    assert command[command.index("--ipc") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges:true" in command
    assert "--privileged" not in command
    assert "--device" not in command
    assert "--pid" not in command
    assert "/var/run/docker.sock" not in " ".join(command)
    assert evidence.exit_code == 0


def test_requires_validated_plan_and_supported_enabled_profile(tmp_path):
    fake = FakeDocker()
    with pytest.raises(SandboxUnavailable, match="not validated"):
        runner(tmp_path, fake).execute(plan(validated=False))
    with pytest.raises(SandboxUnavailable, match="unsupported"):
        runner(tmp_path, fake).execute(plan("restricted_network"))
    with pytest.raises(SandboxUnavailable, match="unsupported"):
        runner(tmp_path, fake).execute(plan("agent_supplied"))
    assert not fake.commands


@pytest.mark.parametrize("architecture", ["arm64", "aarch64", "amd64", "x86_64"])
def test_accepts_supported_daemon_architectures(tmp_path, architecture):
    fake = FakeDocker(architecture=architecture)
    evidence = runner(tmp_path, fake).execute(plan())
    assert evidence.exit_code == 0
    assert any(command[1] == "run" for command in fake.commands)


def test_rejects_unsupported_architecture_and_wrong_digest(tmp_path):
    wrong_arch = FakeDocker(architecture="s390x")
    with pytest.raises(SandboxUnavailable, match="not allowed"):
        runner(tmp_path, wrong_arch).execute(plan())
    assert not any(command[1] == "run" for command in wrong_arch.commands)

    wrong_digest = FakeDocker(digest_matches=False)
    with pytest.raises(SandboxUnavailable, match="digest"):
        runner(tmp_path, wrong_digest).execute(plan())
    assert not any(command[1] == "run" for command in wrong_digest.commands)


def test_readonly_input_is_a_staged_copy_and_mounted_readonly(tmp_path):
    fake = FakeDocker()
    source = tmp_path / "workspace" / "data" / "message.txt"
    source.parent.mkdir(parents=True)
    source.write_text("safe fixture", encoding="utf-8")

    def inspect_staging(command):
        staging = mount_source(command, "/traceguard/input")
        copied = staging / "data" / "message.txt"
        assert copied.read_text(encoding="utf-8") == "safe fixture"
        assert copied.stat().st_mode & 0o222 == 0
        source.write_text("host changed", encoding="utf-8")
        assert copied.read_text(encoding="utf-8") == "safe fixture"
        assert "readonly" in next(value for value in command if "dst=/traceguard/input" in value)

    fake.on_run = inspect_staging
    evidence = runner(tmp_path, fake).execute(plan("readonly_input", inputs=["data"]))
    assert evidence.exit_code == 0
    staging_path = mount_source(docker_run(fake), "/traceguard/input")
    assert not staging_path.exists()


def test_isolated_compute_rejects_inputs_and_readonly_rejects_escape(tmp_path):
    fake = FakeDocker()
    with pytest.raises(SandboxUnavailable, match="does not accept"):
        runner(tmp_path, fake).execute(plan(inputs=["secret.txt"]))

    with pytest.raises(SandboxUnavailable, match="outside the workspace"):
        runner(tmp_path, fake).execute(plan("readonly_input", inputs=["../secret.txt"]))


def test_readonly_input_rejects_symlinks(tmp_path):
    fake = FakeDocker()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "credential"
    outside.write_text("canary", encoding="utf-8")
    (workspace / "link").symlink_to(outside)
    with pytest.raises(SandboxUnavailable, match="symbolic-link"):
        runner(tmp_path, fake).execute(plan("readonly_input", inputs=["link"]))

    internal = workspace / "internal"
    internal.mkdir()
    (internal / "data.txt").write_text("canary", encoding="utf-8")
    (workspace / "linked-directory").symlink_to(internal)
    with pytest.raises(SandboxUnavailable, match="symbolic-link"):
        runner(tmp_path, fake).execute(plan("readonly_input", inputs=["linked-directory/data.txt"]))


def test_artifact_build_inspects_limits_persists_and_cleans_staging(tmp_path):
    fake = FakeDocker()

    def create_artifact(command):
        output = mount_source(command, "/traceguard/output")
        (output / "nested").mkdir()
        (output / "nested" / "report.txt").write_text("result", encoding="utf-8")

    fake.on_run = create_artifact
    evidence = runner(tmp_path, fake).execute(plan("artifact_build"))

    assert evidence.files_changed == ["nested/report.txt"]
    assert evidence.artifact_bytes == 6
    assert evidence.artifact_directory is not None
    persisted = Path(evidence.artifact_directory)
    assert (persisted / "nested" / "report.txt").read_text(encoding="utf-8") == "result"
    staging_path = mount_source(docker_run(fake), "/traceguard/output")
    assert not staging_path.exists()
    assert any(command[1:3] == ["rm", "--force"] for command in fake.commands)


def test_artifact_build_fails_closed_on_oversized_or_symlink_output(tmp_path):
    fake = FakeDocker()

    def create_large_artifact(command):
        output = mount_source(command, "/traceguard/output")
        (output / "large.bin").write_bytes(b"x" * (8_388_608 + 1))

    fake.on_run = create_large_artifact
    with pytest.raises(EvidenceCollectionError, match="per-file"):
        runner(tmp_path, fake).execute(plan("artifact_build"))
    assert any(command[1:3] == ["rm", "--force"] for command in fake.commands)

    fake_link = FakeDocker()

    def create_link(command):
        output = mount_source(command, "/traceguard/output")
        (output / "escape").symlink_to("/etc/passwd")

    fake_link.on_run = create_link
    with pytest.raises(EvidenceCollectionError, match="symbolic links"):
        runner(tmp_path, fake_link).execute(plan("artifact_build"))


def test_bounds_stdout_and_stderr_separately_and_classifies_blocks(tmp_path):
    fake = FakeDocker(
        run_stdout="x" * 70_000,
        run_stderr=("y" * 70_000) + " permission denied",
    )
    evidence = runner(tmp_path, fake).execute(plan())
    assert len(evidence.stdout.encode()) == 65_536
    assert len(evidence.stderr.encode()) == 65_536
    assert evidence.stdout_truncated is True
    assert evidence.stderr_truncated is True

    classified = FakeDocker(run_stderr="connect: network is unreachable")
    evidence = runner(tmp_path, classified).execute(plan())
    assert evidence.blocked_operations == ["network"]


def test_default_process_capture_retains_only_bounded_output():
    result = _run_bounded_command(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('o'*10000); sys.stderr.write('e'*10000)",
        ],
        timeout=5,
        limit=1024,
    )
    assert result.returncode == 0
    assert len(result.stdout.encode()) == 1025
    assert len(result.stderr.encode()) == 1025


def test_parses_docker_resource_units():
    assert _parse_docker_bytes("12.5MiB") == 13_107_200
    assert _parse_docker_bytes("1.2 GB") == 1_200_000_000
    assert _parse_docker_bytes("unknown") is None


def test_timeout_records_bounded_evidence_and_always_cleans_container(tmp_path):
    class TimeoutDocker(FakeDocker):
        def __call__(self, command, **kwargs):
            if command[1] == "run":
                self.commands.append(command)
                raise subprocess.TimeoutExpired(
                    command,
                    kwargs["timeout"],
                    output="partial",
                    stderr="stopped",
                )
            return super().__call__(command, **kwargs)

    fake = TimeoutDocker()
    evidence = runner(tmp_path, fake).execute(plan())
    assert evidence.timed_out is True
    assert evidence.exit_code is None
    assert evidence.stdout == "partial"
    assert evidence.blocked_operations == ["timeout"]
    assert any(command[1:3] == ["rm", "--force"] for command in fake.commands)


def test_cancellation_always_cleans_container_and_staging(tmp_path):
    class CancelDocker(FakeDocker):
        staging_path = None

        def __call__(self, command, **kwargs):
            if command[1] == "run":
                self.commands.append(command)
                self.staging_path = mount_source(command, "/traceguard/input")
                raise KeyboardInterrupt
            return super().__call__(command, **kwargs)

    fake = CancelDocker()
    source = tmp_path / "workspace" / "input.txt"
    source.parent.mkdir(parents=True)
    source.write_text("canary", encoding="utf-8")
    with pytest.raises(KeyboardInterrupt):
        runner(tmp_path, fake).execute(plan("readonly_input", inputs=["input.txt"]))
    assert any(command[1:3] == ["rm", "--force"] for command in fake.commands)
    assert fake.staging_path is not None
    assert not fake.staging_path.exists()


def test_fails_closed_when_container_cleanup_cannot_be_verified(tmp_path):
    class CleanupFailureDocker(FakeDocker):
        def __call__(self, command, **kwargs):
            if command[1:3] == ["rm", "--force"]:
                self.commands.append(command)
                return subprocess.CompletedProcess(command, 2, "", "daemon error")
            return super().__call__(command, **kwargs)

    with pytest.raises(EvidenceCollectionError, match="cleanup"):
        runner(tmp_path, CleanupFailureDocker()).execute(plan())


def test_fails_closed_when_docker_cli_is_unavailable(tmp_path):
    def missing(*args, **kwargs):
        raise FileNotFoundError

    sandbox = ContainerRunner(
        CONFIG_PATH,
        workspace_root=tmp_path,
        artifact_root=tmp_path / "artifacts",
        executor=missing,
    )
    with pytest.raises(SandboxUnavailable, match="Docker CLI"):
        sandbox.execute(plan())
