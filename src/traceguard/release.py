"""Fail-closed validation for container release inputs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_IMAGE_LINE_RE = re.compile(r"^(?P<indent>\s*)image:\s*(?P<value>[^#\r\n]+?)(?:\s+#.*)?$")
_PLACEHOLDER_MARKERS = ("replace", "placeholder", "changeme", "todo")


class ReleaseValidationError(ValueError):
    """Raised when an image reference cannot safely identify a release artifact."""


@dataclass(frozen=True)
class ManifestImage:
    """An image field discovered in a Kubernetes manifest."""

    path: Path
    line: int
    value: str


def validate_image_digest(image: str, *, label: str) -> str:
    """Return a canonical immutable image reference or raise a fail-closed error.

    Tags, non-sha256 algorithms, malformed repository names, and known template
    markers are intentionally rejected. A digest is syntactically validated here;
    registry existence and signature verification belong to the release pipeline.
    """

    candidate = image.strip()
    if not candidate or candidate != image or any(character.isspace() for character in candidate):
        raise ReleaseValidationError(f"{label} must be a non-empty image digest without whitespace")
    if candidate.count("@") != 1:
        raise ReleaseValidationError(f"{label} must use exactly one @sha256 digest separator")

    repository, digest = candidate.split("@", 1)
    if not repository or not _DIGEST_RE.fullmatch(digest):
        raise ReleaseValidationError(
            f"{label} must be an immutable image reference ending in @sha256:<64 lowercase hex>"
        )
    if any(marker in candidate.lower() for marker in _PLACEHOLDER_MARKERS):
        raise ReleaseValidationError(f"{label} contains a placeholder or example value")

    parts = repository.split("/")
    for index, part in enumerate(parts):
        if index == 0 and len(parts) > 1 and ":" in part:
            host, separator, port = part.rpartition(":")
            if (
                not separator
                or not _REPOSITORY_COMPONENT_RE.fullmatch(host)
                or not port.isdecimal()
            ):
                raise ReleaseValidationError(f"{label} has an invalid registry port")
        elif not _REPOSITORY_COMPONENT_RE.fullmatch(part):
            if index == len(parts) - 1 and ":" in part:
                raise ReleaseValidationError(f"{label} must not include a mutable image tag")
            raise ReleaseValidationError(f"{label} has an invalid repository name: {repository!r}")
    return candidate


def validate_dockerfile(dockerfile: Path, *, base_image: str) -> None:
    """Require a caller-supplied immutable base image for the Docker build."""

    try:
        contents = dockerfile.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseValidationError(f"cannot read Dockerfile {dockerfile}: {exc}") from exc

    arg_lines = [
        line.strip()
        for line in re.findall(
            r"^\s*ARG\s+PYTHON_IMAGE(?:\s*=\s*[^\s#]+)?\s*$", contents, re.MULTILINE
        )
    ]
    from_pattern = re.compile(r"^\s*FROM\s+\$\{PYTHON_IMAGE\}(?:\s+AS\s+\w+)?\s*$", re.MULTILINE)
    if not arg_lines or any(line != "ARG PYTHON_IMAGE" for line in arg_lines):
        raise ReleaseValidationError(
            f"{dockerfile} must declare ARG PYTHON_IMAGE without a mutable default"
        )
    if not from_pattern.search(contents):
        raise ReleaseValidationError(f"{dockerfile} must build FROM ${{PYTHON_IMAGE}}")
    validate_image_digest(base_image, label="PYTHON_IMAGE")


def manifest_images(manifest: Path) -> list[ManifestImage]:
    """Extract Kubernetes ``image:`` values without loading untrusted YAML objects."""

    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ReleaseValidationError(f"cannot read manifest {manifest}: {exc}") from exc
    images: list[ManifestImage] = []
    for line_number, text in enumerate(lines, start=1):
        match = _IMAGE_LINE_RE.match(text)
        if match:
            images.append(
                ManifestImage(
                    path=manifest,
                    line=line_number,
                    value=match.group("value").strip().strip("\"'"),
                )
            )
    if not images:
        raise ReleaseValidationError(f"{manifest} contains no Kubernetes image fields")
    return images


def validate_manifest(manifest: Path, *, release_image: str | None = None) -> None:
    """Validate every manifest image, optionally rendering the release placeholder."""

    replacement = (
        validate_image_digest(release_image, label="TRACEGUARD_RELEASE_IMAGE")
        if release_image is not None
        else None
    )
    for image in manifest_images(manifest):
        value = (
            replacement
            if "REPLACE_WITH_RELEASE_DIGEST" in image.value and replacement
            else image.value
        )
        try:
            validate_image_digest(value, label=f"{image.path}:{image.line} image")
        except ReleaseValidationError as exc:
            raise ReleaseValidationError(str(exc)) from exc


def render_manifest(manifest: Path, output: Path, *, release_image: str | None = None) -> None:
    """Write a validated manifest without overwriting the template or an existing artifact.

    This validates image-reference syntax only. Kubernetes schema validation and registry
    verification are separate release gates.
    """
    validate_manifest(manifest, release_image=release_image)
    lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
    for image in manifest_images(manifest):
        if "REPLACE_WITH_RELEASE_DIGEST" in image.value and release_image is not None:
            lines[image.line - 1] = lines[image.line - 1].replace(image.value, release_image, 1)
    rendered = "".join(lines)
    if "REPLACE_WITH_RELEASE_DIGEST" in rendered:
        raise ReleaseValidationError("rendered manifest still contains a release placeholder")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            stream.write(rendered)
    except OSError as exc:
        raise ReleaseValidationError(f"cannot write new manifest {output}: {exc}") from exc


def validate_release_artifacts(
    *, dockerfile: Path, manifests: list[Path], base_image: str, release_image: str | None = None
) -> None:
    """Validate all supplied release inputs before building or applying them."""

    if not manifests:
        raise ReleaseValidationError("at least one Kubernetes manifest is required")
    validate_dockerfile(dockerfile, base_image=base_image)
    for manifest in manifests:
        validate_manifest(manifest, release_image=release_image)
