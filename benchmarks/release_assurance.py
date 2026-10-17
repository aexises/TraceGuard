"""Validate maintainer-supplied release evidence; never manufacture external assurance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from traceguard.tools.filesystem import read_confined

GOVERNED = (
    "src",
    "benchmarks",
    "react_agentdojo",
    "configs",
    ".github",
    "tests",
    "pyproject.toml",
    "uv.lock",
    "Dockerfile",
    ".dockerignore",
)
EVIDENCE_PATH = "configs/release_evidence.json"


def source_digest(root: Path) -> str:
    """Bind review to governed source, excluding only the evidence envelope itself."""
    digest = hashlib.sha256()
    for entry in GOVERNED:
        path = root / entry
        paths = sorted(path.rglob("*")) if path.is_dir() else [path]
        for item in paths:
            if "__pycache__" in item.parts or item.suffix == ".pyc":
                continue
            if item.is_dir() and not item.is_symlink():
                continue
            relative = item.relative_to(root).as_posix()
            if relative == EVIDENCE_PATH:
                continue
            data = read_confined(root, relative, max_bytes=16 * 1024 * 1024)
            digest.update(relative.encode() + b"\0" + hashlib.sha256(data).digest())
    return digest.hexdigest()


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: Literal["independent-review", "pilot", "heldout-evaluation", "license-approval"]
    organization: str = Field(min_length=1, max_length=200)
    accountable_person: str = Field(min_length=1, max_length=200)
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference: str = Field(pattern=r"^https://\S+$", max_length=2000)
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted: Literal[True]
    unresolved_blockers: Literal[0]

    @field_validator("accepted", "unresolved_blockers", mode="before")
    @classmethod
    def exact_types(cls, value, info):
        expected = bool if info.field_name == "accepted" else int
        if type(value) is not expected:
            raise ValueError("evidence flags must use exact JSON boolean/integer types")
        return value


class ReleaseEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewed_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    maintainer_organization: str = Field(min_length=1, max_length=200)
    license_spdx: str = Field(min_length=1, max_length=100)
    license_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: list[Evidence] = Field(min_length=5, max_length=32)


def validate(root: Path, raw: dict) -> dict:
    envelope = ReleaseEvidence.model_validate(raw)
    digest = source_digest(root)
    if digest != envelope.source_digest:
        raise ValueError("release evidence does not bind the current governed source")
    license_data = read_confined(root, "LICENSE", max_bytes=1024 * 1024)
    if (
        not license_data.strip()
        or hashlib.sha256(license_data).hexdigest() != envelope.license_sha256
    ):
        raise ValueError("missing or changed owner-approved LICENSE")
    kinds: dict[str, list[Evidence]] = {}
    references, hashes = set(), set()
    for record in envelope.evidence:
        if record.source_digest != digest:
            raise ValueError("evidence is for different governed source")
        data = read_confined(root, record.path, max_bytes=16 * 1024 * 1024)
        if not data.strip() or hashlib.sha256(data).hexdigest() != record.sha256:
            raise ValueError("missing or changed evidence document")
        if record.reference in references or record.sha256 in hashes:
            raise ValueError("duplicate evidence documents or references")
        references.add(record.reference)
        hashes.add(record.sha256)
        kinds.setdefault(record.kind, []).append(record)
    if not all(
        kinds.get(kind)
        for kind in ("independent-review", "pilot", "heldout-evaluation", "license-approval")
    ):
        raise ValueError("missing external review, pilots, evaluation or owner license approval")
    if any(
        r.organization.casefold().strip() == envelope.maintainer_organization.casefold().strip()
        for r in kinds["independent-review"]
    ):
        raise ValueError("independent reviewer must be outside the maintainer organization")
    if len({r.organization.casefold().strip() for r in kinds["pilot"]}) < 2:
        raise ValueError("two distinct application pilot organizations are required")
    return {
        "source_digest": digest,
        "reviewed_revision": envelope.reviewed_revision,
        "evidence_records": len(envelope.evidence),
        "license_spdx": envelope.license_spdx,
        "scope": "document integrity and maintainer assertions; human verification required",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence", type=Path, default=Path(EVIDENCE_PATH))
    parser.add_argument("--digest-only", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.digest_only:
        print(source_digest(root))
    else:
        if not (root / args.evidence).is_file():
            parser.error(
                "release evidence is missing; independent review, pilots and license pending"
            )
        raw = json.loads(read_confined(root, str(args.evidence), max_bytes=1024 * 1024))
        print(json.dumps(validate(root, raw), indent=2))


if __name__ == "__main__":
    main()
