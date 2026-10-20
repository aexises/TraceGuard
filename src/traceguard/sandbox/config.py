"""Strict, trusted configuration for Docker containment profiles."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from traceguard.types import SandboxLimits, StrictModel

PINNED_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$")
ENABLED_PROFILES = {"isolated_compute", "readonly_input", "artifact_build"}


class ArtifactLimits(StrictModel):
    max_files: int = Field(default=64, ge=1, le=4096)
    max_total_bytes: int = Field(default=16_777_216, ge=1_024, le=16_777_216)
    max_file_bytes: int = Field(default=8_388_608, ge=1_024, le=8_388_608)
    max_entries: int = Field(default=256, ge=1, le=4096)
    max_depth: int = Field(default=16, ge=1, le=32)
    max_inodes: int = Field(default=512, ge=16, le=8192)


class InputLimits(StrictModel):
    max_entries: int = Field(default=1024, ge=1, le=16_384)
    max_bytes: int = Field(default=16_777_216, ge=1, le=268_435_456)
    max_file_bytes: int = Field(default=8_388_608, ge=1, le=268_435_456)
    max_depth: int = Field(default=16, ge=1, le=32)
    timeout_seconds: float = Field(default=5, gt=0, le=30)


class SandboxProfile(StrictModel):
    enabled: bool
    network: Literal["none", "allowlist"]
    input_mode: Literal["none", "copy_readonly"]
    output_mode: Literal["none", "allowlisted"]
    limits: SandboxLimits
    tmpfs_mb: int = Field(default=64, ge=8, le=1024)
    artifact_limits: ArtifactLimits = Field(default_factory=ArtifactLimits)
    input_limits: InputLimits = Field(default_factory=InputLimits)


class SandboxConfiguration(StrictModel):
    version: str = Field(min_length=1)
    image: str
    allowed_architectures: list[Literal["arm64", "amd64"]] = Field(min_length=1)
    container_user: str = Field(pattern=r"^[0-9]+:[0-9]+$")
    profiles: dict[str, SandboxProfile]

    @model_validator(mode="after")
    def validate_safety_boundary(self) -> SandboxConfiguration:
        if not PINNED_IMAGE_RE.fullmatch(self.image):
            raise ValueError("sandbox image must use an immutable sha256 digest")
        unknown = set(self.profiles) - (ENABLED_PROFILES | {"restricted_network"})
        if unknown:
            raise ValueError(f"unsupported sandbox profiles in trusted config: {sorted(unknown)}")
        missing = ENABLED_PROFILES - set(self.profiles)
        if missing:
            raise ValueError(f"missing sandbox profiles: {sorted(missing)}")
        for name in ENABLED_PROFILES:
            profile = self.profiles[name]
            if not profile.enabled or profile.network != "none":
                raise ValueError(f"{name} must be enabled with network=none")
        restricted = self.profiles.get("restricted_network")
        if restricted is None or restricted.enabled:
            raise ValueError("restricted_network must remain present and disabled")
        return self


def load_sandbox_configuration(path: Path) -> SandboxConfiguration:
    """Load a strict profile file; unknown keys and unsafe values fail closed."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load trusted sandbox configuration: {path}") from exc
    return SandboxConfiguration.model_validate(raw)


def default_sandbox_configuration_path() -> Path:
    source_tree_path = Path(__file__).resolve().parents[3] / "configs" / "sandbox_profiles.json"
    if source_tree_path.is_file():
        return source_tree_path
    return Path(__file__).resolve().parents[1] / "data" / "configs" / "sandbox_profiles.json"
