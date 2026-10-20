"""Three-container conformance, not an external application pilot or model efficacy benchmark."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from traceguard.isolation_fixture import prepare

_READINESS_PROBE = """
import socket
import sys
import time

deadline = time.monotonic() + float(sys.argv[2])
while True:
    try:
        with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
            break
    except OSError as exc:
        if time.monotonic() >= deadline:
            raise TimeoutError("service listener readiness deadline exceeded") from exc
        time.sleep(0.1)
"""


def docker(*args, timeout=60):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Docker operation failed: {args[0]}: {result.stderr[-4096:]}")
    return result.stdout.strip()


def wait_for_listener(container: str) -> None:
    # Probe before sending any action. Never retry a possibly dispatched effect.
    docker("exec", container, "python", "-c", _READINESS_PROBE, "9443", "10", timeout=15)


def run(image: str) -> dict:
    if os.getuid() == 0:
        raise ValueError("run this fixture as a non-root host user")
    prefix = "traceguard-isolation-" + uuid4().hex[:12]
    names = {role: prefix + "-" + role for role in ["authority", "executor", "agent"]}
    network = prefix + "-network"
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        root = Path(temporary).resolve() / "fixture"
        fixture = prepare(root, container_paths=True)
        common = [
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--cpus",
            "1",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16777216,nr_inodes=512",
        ]
        created_network = False
        try:
            docker("network", "create", "--internal", network)
            created_network = True
            assert docker("network", "inspect", "--format", "{{.Internal}}", network) == "true"
            for role in ["authority", "executor"]:
                docker(
                    "run",
                    "-d",
                    "--name",
                    names[role],
                    "--network-alias",
                    role,
                    *common,
                    "--mount",
                    f"type=bind,src={fixture['directories'][role]},dst=/config,readonly",
                    "--mount",
                    f"type=bind,src={root / (role + '-state')},dst=/state",
                    image,
                    "python",
                    "-m",
                    "traceguard.isolated",
                    "--config",
                    "/config/config.json",
                )
                wait_for_listener(names[role])
            agent_command = [
                "run",
                "--rm",
                "--name",
                names["agent"],
                *common,
                "--mount",
                f"type=bind,src={fixture['directories']['agent']},dst=/config,readonly",
                image,
                "python",
                "-m",
                "traceguard.isolation_probe",
            ]
            first = json.loads(docker(*agent_command, timeout=60))
            docker("restart", names["authority"])
            wait_for_listener(names["authority"])
            second = json.loads(docker(*agent_command, timeout=60))
            reports = list(
                (root / "executor-state/artifacts/released").glob("*/reports/report.txt")
            )
            assert len(reports) == 1 and reports[0].read_text() == "Approved public report"
            assert not list(
                (root / "executor-state/artifacts/released").glob("*/reports/unapproved.txt")
            )
            result = {
                "scope": "disposable isolated report integration; no live model or external pilot",
                "image": image,
                "first_run": first,
                "after_issuer_restart": second,
                "one_authorized_report": True,
                "internal_network_verified": True,
            }
        except BaseException:
            for role in ["authority", "executor"]:
                logs = subprocess.run(
                    ["docker", "logs", names[role]], capture_output=True, text=True
                )
                if logs.stderr.strip():
                    print(
                        f"{role} diagnostics: {logs.stderr[-4096:]}", file=__import__("sys").stderr
                    )
            raise
        finally:
            for name in names.values():
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)
            if created_network:
                docker("network", "rm", network)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
