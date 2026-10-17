from pathlib import Path

import pytest

from traceguard.cli import main
from traceguard.release import (
    ReleaseValidationError,
    render_manifest,
    validate_dockerfile,
    validate_image_digest,
    validate_manifest,
)

VALID_BASE_IMAGE = "python@sha256:" + "a" * 64
VALID_RELEASE_IMAGE = "registry.invalid/traceguard/api@sha256:" + "b" * 64


def test_image_digest_requires_an_immutable_sha256_reference() -> None:
    assert validate_image_digest(VALID_RELEASE_IMAGE, label="image") == VALID_RELEASE_IMAGE
    for image in (
        "python:3.11-slim",
        "ghcr.io/example/traceguard@sha256:REPLACE_WITH_RELEASE_DIGEST",
        "registry.example.invalid/traceguard/api@sha256:" + "A" * 64,
        "registry.example.invalid/traceguard/api:latest@sha256:" + "a" * 64,
    ):
        with pytest.raises(ReleaseValidationError):
            validate_image_digest(image, label="image")


def test_manifest_placeholder_fails_without_a_release_digest() -> None:
    with pytest.raises(ReleaseValidationError, match="immutable image reference"):
        validate_manifest(Path("deploy/kubernetes/control-plane.yaml"))


def test_dockerfile_rejects_a_mutable_python_image_default(tmp_path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG PYTHON_IMAGE=python:3.11-slim\nFROM ${PYTHON_IMAGE}\n")
    with pytest.raises(ReleaseValidationError, match="without a mutable default"):
        validate_dockerfile(dockerfile, base_image=VALID_BASE_IMAGE)


def test_release_dockerfile_has_a_build_time_digest_check() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert "ARG PYTHON_IMAGE\nFROM ${PYTHON_IMAGE}" in dockerfile
    assert "PYTHON_IMAGE must be an immutable sha256 digest" in dockerfile


def test_release_validation_renders_only_a_valid_release_digest(capsys) -> None:
    assert (
        main(
            [
                "release-validate",
                "--base-image",
                VALID_BASE_IMAGE,
                "--release-image",
                VALID_RELEASE_IMAGE,
            ]
        )
        == 0
    )
    assert '"valid": true' in capsys.readouterr().out


def test_release_validation_rejects_the_previous_mutable_base_image(capsys) -> None:
    assert main(["release-validate", "--base-image", "python:3.11-slim"]) == 1
    assert "@sha256 digest separator" in capsys.readouterr().err


def test_rendered_manifest_is_valid_without_substitution_and_template_is_unchanged(tmp_path):
    template = Path("deploy/kubernetes/control-plane.yaml")
    original = template.read_bytes()
    output = tmp_path / "release.yaml"
    assert (
        main(
            [
                "release-validate",
                "--base-image",
                VALID_BASE_IMAGE,
                "--release-image",
                VALID_RELEASE_IMAGE,
                "--output-manifest",
                str(output),
            ]
        )
        == 0
    )
    validate_manifest(output)
    assert VALID_RELEASE_IMAGE in output.read_text()
    assert "REPLACE_WITH_RELEASE_DIGEST" not in output.read_text()
    assert template.read_bytes() == original


def test_render_rejects_invalid_image_without_creating_artifact(tmp_path):
    output = tmp_path / "release.yaml"
    with pytest.raises(ReleaseValidationError):
        render_manifest(
            Path("deploy/kubernetes/control-plane.yaml"), output, release_image="traceguard:latest"
        )
    assert not output.exists()


def test_render_never_overwrites_existing_file(tmp_path):
    output = tmp_path / "release.yaml"
    output.write_text("keep me")
    with pytest.raises(ReleaseValidationError, match="cannot write new manifest"):
        render_manifest(
            Path("deploy/kubernetes/control-plane.yaml"), output, release_image=VALID_RELEASE_IMAGE
        )
    assert output.read_text() == "keep me"


def test_render_rejects_multiple_input_manifests(tmp_path):
    template = "deploy/kubernetes/control-plane.yaml"
    output = tmp_path / "release.yaml"
    assert (
        main(
            [
                "release-validate",
                "--base-image",
                VALID_BASE_IMAGE,
                "--release-image",
                VALID_RELEASE_IMAGE,
                "--manifest",
                template,
                "--manifest",
                template,
                "--output-manifest",
                str(output),
            ]
        )
        == 1
    )
    assert not output.exists()
