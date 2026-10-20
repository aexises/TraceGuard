"""Reproducible, fail-closed dependency and redacted secret scans of a checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path

from benchmarks.release_assurance import source_digest
from traceguard.tools.filesystem import read_confined, write_confined


def run(command: list[str], *, root: Path) -> None:
    # Scanner diagnostics can contain source material; keep them private, even on errors.
    result = subprocess.run(command, cwd=root, capture_output=True, timeout=900)
    if result.returncode:
        raise RuntimeError(f"{Path(command[0]).name} failed (status {result.returncode})")


def extract_scanner(archive: bytes, digest: str, destination: Path) -> Path:
    if hashlib.sha256(archive).hexdigest() != digest:
        raise ValueError("scanner archive checksum mismatch")
    path = destination / "scanner.tar.gz"
    path.write_bytes(archive)
    with tarfile.open(path) as bundle:
        member = bundle.getmember("gitleaks")
        if not member.isfile() or member.size > 64 * 1024 * 1024:
            raise ValueError("invalid scanner binary")
        source = bundle.extractfile(member)
        if source is None:
            raise ValueError("missing scanner binary")
        binary = destination / "gitleaks"
        binary.write_bytes(source.read())
    binary.chmod(0o700)
    return binary


def stage_sources(root: Path, destination: Path) -> None:
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
    ).split(b"\0")
    total = 0
    for name in sorted(set(names) - {b""}):
        relative = name.decode("utf-8")
        # No broad test/source exclusions: ignored local credentials are deliberately
        # outside this publication scan; tracked credential files are scanned.
        if not (root / relative).exists() and not (root / relative).is_symlink():
            continue  # tracked deletion
        data = read_confined(root, relative, max_bytes=16 * 1024 * 1024)
        total += len(data)
        if total > 256 * 1024 * 1024:
            raise ValueError("source scan staging exceeds 256 MiB")
        write_confined(destination, relative, data)


def scan(root: Path, output: Path, *, archive_path: Path | None = None) -> None:
    root, output = root.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "scan.json").unlink(missing_ok=True)
    if (
        subprocess.check_output(["git", "rev-parse", "--is-shallow-repository"], cwd=root).strip()
        != b"false"
    ):
        raise ValueError("full fetched Git history is required")
    tools = json.loads((root / "configs/security_tools.json").read_text())
    before = source_digest(root)
    architecture = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x64"}.get(
        platform.machine().lower(), "unsupported"
    )
    target = f"{platform.system().lower()}_{architecture}"
    checksum = tools["archives"][target]  # unsupported platforms fail closed
    with tempfile.TemporaryDirectory(prefix="traceguard-scans-") as temporary:
        directory = Path(temporary).resolve()
        if archive_path:
            archive = archive_path.read_bytes()
        else:
            version = tools["gitleaks_version"]
            url = (
                f"https://github.com/gitleaks/gitleaks/releases/download/v{version}/"
                f"gitleaks_{version}_{target}.tar.gz"
            )
            with urllib.request.urlopen(url, timeout=60) as response:
                archive = response.read(32 * 1024 * 1024 + 1)
            if len(archive) > 32 * 1024 * 1024:
                raise ValueError("scanner download exceeds limit")
        scanner = str(extract_scanner(archive, checksum, directory))
        common = ["--redact=100", "--no-banner", "--report-format", "json"]
        run(
            [
                scanner,
                "git",
                *common,
                "--report-path",
                str(output / "history-secrets.json"),
                "--log-opts=--all",
                ".",
            ],
            root=root,
        )
        stage = directory / "source"
        stage.mkdir(mode=0o700)
        stage_sources(root, stage)
        run(
            [
                scanner,
                "dir",
                *common,
                "--report-path",
                str(output / "source-secrets.json"),
                str(stage),
            ],
            root=root,
        )
    profiles = [("core", []), ("all-extras", ["--all-extras"])]
    vcs_sources = []
    for native, excluded in (("inspect", "inspect-evals"), ("agentdyn", "agentdojo")):
        project = root / "benchmarks/environments" / native
        lock = tomllib.loads((project / "uv.lock").read_text())
        vcs = [p for p in lock["package"] if "git" in p.get("source", {})]
        if len(vcs) != 1 or vcs[0]["name"] != excluded:
            raise ValueError("unexpected unauditable native source package")
        vcs_sources.append({"profile": native, "package": excluded, "source": vcs[0]["source"]})
        profiles.append((native, ["--project", str(project), "--no-emit-package", excluded]))
    for profile, extras in profiles:
        requirements = output / f"{profile}-requirements.txt"
        run(
            [
                "uv",
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                *extras,
                "--format",
                "requirements-txt",
                "--output-file",
                str(requirements),
            ],
            root=root,
        )
        audit = [
            "uv",
            "tool",
            "run",
            "--python",
            str(root / ".venv/bin/python"),
            "--from",
            f"pip-audit=={tools['pip_audit_version']}",
            "pip-audit",
            "--disable-pip",
            "--require-hashes",
            "--strict",
            "--progress-spinner",
            "off",
            "-r",
            str(requirements),
        ]
        run([*audit, "-f", "json", "-o", str(output / f"{profile}-advisories.json")], root=root)
        run([*audit, "-f", "cyclonedx-json", "-o", str(output / f"{profile}-sbom.json")], root=root)
    if source_digest(root) != before:
        raise ValueError("governed source changed during scanning")
    (output / "scan.json").write_text(
        json.dumps(
            {
                "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root)
                .decode()
                .strip(),
                "tools": tools,
                "source_digest": before,
                "profiles": [name for name, _ in profiles],
                "unaudited_vcs_sources": vcs_sources,
                "known_advisories": 0,
                "secret_findings": 0,
                "scope": "fetched history, publication source and current-platform dependencies",
            },
            indent=2,
        )
        + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gitleaks-archive", type=Path)
    args = parser.parse_args()
    scan(args.root, args.output, archive_path=args.gitleaks_archive)


if __name__ == "__main__":
    main()
