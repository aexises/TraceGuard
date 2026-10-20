"""Operational commands for the TraceGuard security framework."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from traceguard.release import ReleaseValidationError, render_manifest, validate_release_artifacts
from traceguard.sandbox.config import default_sandbox_configuration_path
from traceguard.sandbox.runner import ContainerRunner, SandboxUnavailable
from traceguard.security import SecuredTools
from traceguard.tools.registry import default_registry
from traceguard.types import TaskAuthority, ToolCall


def _smoke() -> int:
    with TemporaryDirectory(prefix="traceguard-smoke-") as temporary:
        root = Path(temporary)
        boundary = SecuredTools(
            default_registry(root, root / "artifacts"),
            TaskAuthority(allowed_tools=["calculator"]),
            task_id="smoke",
        )
        result = boundary.execute_call(
            "Calculate",
            ToolCall(
                task_id="smoke",
                step_id=0,
                tool_name="calculator",
                arguments={"expression": "12 * 7"},
            ),
            [],
        )
        if result.observation is None or result.observation.content != "84":
            raise RuntimeError("strict execution smoke check failed")
        print(json.dumps({"authorized_result": result.observation.content, "strict": True}))
    return 0


def _sandbox_check(args: argparse.Namespace) -> int:
    runner = ContainerRunner(
        args.config.resolve(),
        workspace_root=args.root.resolve(),
        artifact_root=args.artifacts.resolve(),
    )
    try:
        architecture = runner.check_environment()
    except SandboxUnavailable as exc:
        print(json.dumps({"ready": False, "error": str(exc)}, indent=2))
        return 1
    print(
        json.dumps(
            {
                "ready": True,
                "architecture": architecture,
                "image": runner.image,
                "config_version": runner.config.version,
                "enabled_profiles": sorted(
                    name for name, profile in runner.config.profiles.items() if profile.enabled
                ),
            },
            indent=2,
        )
    )
    return 0


def _release_validate(args: argparse.Namespace) -> int:
    manifests = args.manifest or [Path("deploy/kubernetes/control-plane.yaml")]
    try:
        if args.output_manifest is not None and len(manifests) != 1:
            raise ReleaseValidationError("--output-manifest requires exactly one input manifest")
        validate_release_artifacts(
            dockerfile=args.dockerfile,
            manifests=manifests,
            base_image=args.base_image,
            release_image=args.release_image,
        )
        if args.output_manifest is not None:
            render_manifest(manifests[0], args.output_manifest, release_image=args.release_image)
    except ReleaseValidationError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "valid": True,
                "dockerfile": str(args.dockerfile),
                "manifests": [str(path) for path in manifests],
                "output_manifest": str(args.output_manifest) if args.output_manifest else None,
                "scope": "image-reference syntax; not Kubernetes schema or registry verification",
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="traceguard")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("smoke", help="check explicitly authorized tool execution offline")
    sandbox = commands.add_parser("sandbox-check", help="verify the pinned container boundary")
    sandbox.add_argument("--root", type=Path, default=Path.cwd())
    sandbox.add_argument("--config", type=Path, default=default_sandbox_configuration_path())
    sandbox.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    release = commands.add_parser(
        "release-validate", help="validate immutable deployment references"
    )
    release.add_argument("--dockerfile", type=Path, default=Path("Dockerfile"))
    release.add_argument("--manifest", type=Path, action="append", default=None)
    release.add_argument("--base-image", required=True)
    release.add_argument("--output-manifest", type=Path)
    release.add_argument("--release-image", default=None)
    args = parser.parse_args(argv)
    if args.command == "smoke":
        return _smoke()
    if args.command == "sandbox-check":
        return _sandbox_check(args)
    return _release_validate(args)


if __name__ == "__main__":
    raise SystemExit(main())
