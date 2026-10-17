import copy
import hashlib
import io
import subprocess
import tarfile

import pytest

from benchmarks.release_assurance import source_digest, validate
from benchmarks.release_checks import extract_scanner, run, scan, stage_sources


@pytest.fixture
def candidate(tmp_path):
    for directory in ("src", "benchmarks", "react_agentdojo", "configs", ".github", "tests"):
        (tmp_path / directory).mkdir()
    for name in ("pyproject.toml", "uv.lock", "Dockerfile", ".dockerignore", "LICENSE"):
        (tmp_path / name).write_text("fixture " + name)
    (tmp_path / "src/adapter.py").write_text("raise RuntimeError('fixture only')")
    digest = source_digest(tmp_path)
    records = []
    for index, kind in enumerate(
        ("independent-review", "heldout-evaluation", "license-approval", "pilot", "pilot")
    ):
        data = f"synthetic validator unit fixture {index}".encode()
        name = f"fixture-{index}.txt"
        (tmp_path / name).write_bytes(data)
        records.append(
            {
                "kind": kind,
                "organization": f"fixture-organization-{index}",
                "accountable_person": "fixture tester",
                "source_digest": digest,
                "reference": f"https://example.invalid/fixture/{index}",
                "path": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "accepted": True,
                "unresolved_blockers": 0,
            }
        )
    return tmp_path, {
        "source_digest": digest,
        "reviewed_revision": "a" * 40,
        "maintainer_organization": "fixture-maintainer",
        "license_spdx": "fixture-only",
        "license_sha256": hashlib.sha256((tmp_path / "LICENSE").read_bytes()).hexdigest(),
        "evidence": records,
    }


def test_complete_synthetic_evidence_checks_integrity_only(candidate):
    root, envelope = candidate
    assert validate(root, envelope)["evidence_records"] == 5
    (root / "src/adapter.py").write_text("changed")
    with pytest.raises(ValueError, match="current governed source"):
        validate(root, envelope)


@pytest.mark.parametrize(
    "change",
    [
        "missing-review",
        "same-reviewer",
        "same-pilot",
        "duplicate",
        "not-accepted",
        "blocker",
        "numeric-approval",
        "bool-blocker",
    ],
)
def test_external_assurance_cannot_be_replaced_by_incomplete_or_ambiguous_flags(candidate, change):
    root, envelope = candidate
    envelope = copy.deepcopy(envelope)
    record = envelope["evidence"][0]
    if change == "missing-review":
        record["kind"] = "pilot"
    elif change == "same-reviewer":
        record["organization"] = envelope["maintainer_organization"]
    elif change == "same-pilot":
        envelope["evidence"][-1]["organization"] = envelope["evidence"][-2]["organization"]
    elif change == "duplicate":
        envelope["evidence"][-1] = envelope["evidence"][-2]
    elif change == "not-accepted":
        record["accepted"] = False
    elif change == "blocker":
        record["unresolved_blockers"] = 1
    elif change == "numeric-approval":
        record["accepted"] = 1
    elif change == "bool-blocker":
        record["unresolved_blockers"] = False
    with pytest.raises(ValueError):
        validate(root, envelope)


@pytest.mark.parametrize("target", ["LICENSE", "fixture-0.txt"])
def test_missing_or_changed_documents_fail(candidate, target):
    root, envelope = candidate
    (root / target).write_text("tampered")
    with pytest.raises(ValueError, match="changed"):
        validate(root, envelope)
    (root / target).unlink()
    with pytest.raises((ValueError, OSError)):
        validate(root, envelope)


def test_envelope_is_excluded_without_excluding_policy_changes(candidate):
    root, _ = candidate
    before = source_digest(root)
    (root / "configs/release_evidence.json").write_text("metadata")
    assert source_digest(root) == before
    (root / "configs/policy.json").write_text("new policy")
    assert source_digest(root) != before


def test_scanner_checksum_checked_before_extraction(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        member = tarfile.TarInfo("gitleaks")
        member.type = tarfile.SYMTYPE
        member.linkname = "/tmp/never-extract"
        bundle.addfile(member)
    archive = buffer.getvalue()
    with pytest.raises(ValueError, match="checksum"):
        extract_scanner(archive, "0" * 64, tmp_path)
    with pytest.raises(ValueError, match="invalid scanner"):
        extract_scanner(archive, hashlib.sha256(archive).hexdigest(), tmp_path)


def test_scanner_failure_does_not_echo_source(monkeypatch, tmp_path):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            a[0], 1, stdout=b"sensitive source", stderr=b"sensitive diagnostic"
        ),
    )
    with pytest.raises(RuntimeError) as error:
        run(["scanner"], root=tmp_path)
    assert "sensitive" not in str(error.value)


def test_shallow_history_removes_previous_success_and_fails(monkeypatch, tmp_path):
    output = tmp_path / "reports"
    output.mkdir()
    (output / "scan.json").write_text("old success")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"true\n")
    with pytest.raises(ValueError, match="full fetched"):
        scan(tmp_path, output)
    assert not (output / "scan.json").exists()


def test_publication_staging_includes_tests_and_rejects_aliases(monkeypatch, tmp_path):
    root, stage = tmp_path / "root", tmp_path / "stage"
    root.mkdir()
    stage.mkdir()
    (root / "test_fixture.py").write_text("fixture")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"test_fixture.py\0")
    stage_sources(root, stage)
    assert (stage / "test_fixture.py").read_text() == "fixture"
    (root / "alias").symlink_to(root / "test_fixture.py")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"alias\0")
    with pytest.raises((ValueError, OSError)):
        stage_sources(root, stage)
