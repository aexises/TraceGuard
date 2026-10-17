"""Opt-in harmless canaries against Docker Desktop on the ARM64 evaluation host."""

import json
import os
from pathlib import Path

import pytest

from traceguard.sandbox.runner import ContainerRunner
from traceguard.types import ExecutionPlan, ExecutionTarget, ToolCall

pytestmark = pytest.mark.skipif(
    os.getenv("TRACEGUARD_RUN_DOCKER_TESTS") != "1",
    reason="set TRACEGUARD_RUN_DOCKER_TESTS=1 on the disposable Docker test host",
)

CONFIG_PATH = Path(__file__).parents[2] / "configs" / "sandbox_profiles.json"


def execute(
    tmp_path: Path,
    command: list[str],
    *,
    profile: str = "isolated_compute",
    inputs: list[str] | None = None,
    config_path: Path = CONFIG_PATH,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    runner = ContainerRunner(
        config_path,
        workspace_root=workspace,
        artifact_root=tmp_path / "artifacts",
    )
    call = ToolCall(
        task_id="docker-canary",
        step_id=0,
        tool_name="restricted_command",
        arguments={"command": command},
    )
    return runner.execute(
        ExecutionPlan(
            effective_call=call,
            target=ExecutionTarget.CONTAINER,
            sandbox_profile=profile,
            declared_input_paths=inputs or [],
            validated=True,
            validation_reason="harmless integration canary",
        )
    )


def test_real_container_has_no_network(tmp_path):
    evidence = execute(
        tmp_path,
        [
            "python3",
            "-c",
            ("import socket; socket.create_connection(('example.com', 80), timeout=1)"),
        ],
    )
    assert evidence.exit_code != 0


def test_real_container_cannot_see_undeclared_host_path(tmp_path):
    (tmp_path / "workspace").mkdir()
    canary = tmp_path / "workspace" / "host-only-canary"
    canary.write_text("host only", encoding="utf-8")
    evidence = execute(
        tmp_path,
        [
            "python3",
            "-c",
            (
                "from pathlib import Path; "
                "raise SystemExit(1 if Path('/host-only-canary').exists() else 0)"
            ),
        ],
    )
    assert evidence.exit_code == 0


def test_real_container_output_is_bounded_separately(tmp_path):
    evidence = execute(
        tmp_path,
        [
            "python3",
            "-c",
            "import sys; print('o'*70000); print('e'*70000, file=sys.stderr)",
        ],
    )
    assert evidence.stdout_truncated is True
    assert evidence.stderr_truncated is True
    assert len(evidence.stdout.encode()) <= 65_536
    assert len(evidence.stderr.encode()) <= 65_536


def test_real_container_enforces_process_limit(tmp_path):
    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    raw["profiles"]["isolated_compute"]["limits"]["pids"] = 8
    config = tmp_path / "pids-config.json"
    config.write_text(json.dumps(raw), encoding="utf-8")
    evidence = execute(
        tmp_path,
        [
            "python3",
            "-c",
            (
                "import subprocess,sys\n"
                "children=[]\n"
                "blocked=False\n"
                "try:\n"
                "  for _ in range(20): children.append(subprocess.Popen(['sleep','5']))\n"
                "except OSError:\n"
                "  blocked=True\n"
                "finally:\n"
                "  [child.terminate() for child in children]\n"
                "raise SystemExit(0 if blocked else 1)"
            ),
        ],
        config_path=config,
    )
    assert evidence.exit_code == 0


def test_real_container_times_out_and_is_removed(tmp_path):
    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    raw["profiles"]["isolated_compute"]["limits"]["timeout_seconds"] = 1
    config = tmp_path / "timeout-config.json"
    config.write_text(json.dumps(raw), encoding="utf-8")
    evidence = execute(
        tmp_path,
        ["python3", "-c", "import time; time.sleep(30)"],
        config_path=config,
    )
    assert evidence.timed_out is True
    assert evidence.exit_code is None
    assert "timeout" in evidence.blocked_operations


def test_real_readonly_input_cannot_be_modified(tmp_path):
    (tmp_path / "workspace").mkdir()
    source = tmp_path / "workspace" / "input.txt"
    source.write_text("canary", encoding="utf-8")
    evidence = execute(
        tmp_path,
        [
            "python3",
            "-c",
            ("from pathlib import Path; Path('/traceguard/input/input.txt').write_text('changed')"),
        ],
        profile="readonly_input",
        inputs=["input.txt"],
    )
    assert evidence.exit_code != 0
    assert source.read_text(encoding="utf-8") == "canary"


def test_real_artifact_build_exports_only_inspected_output(tmp_path):
    evidence = execute(
        tmp_path,
        [
            "python3",
            "-c",
            (
                "from pathlib import Path; "
                "Path('/traceguard/output/result.txt').write_text('safe result')"
            ),
        ],
        profile="artifact_build",
    )
    assert evidence.exit_code == 0, evidence.stderr
    assert evidence.files_changed == ["result.txt"]
    assert evidence.artifact_directory is not None
    assert (Path(evidence.artifact_directory) / "result.txt").read_text(
        encoding="utf-8"
    ) == "safe result"
