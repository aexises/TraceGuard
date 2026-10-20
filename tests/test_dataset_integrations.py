import json
import re
import tomllib
from pathlib import Path

import pytest

from benchmarks.checkers import call_matches
from benchmarks.datasets.gateway import SupervisionGateway
from benchmarks.datasets.llmail import (
    LLMailRecord,
    normalize_payload,
    stratified_selection,
    validate_group_disjoint_splits,
)
from benchmarks.datasets.models import AdapterRunRequest
from benchmarks.datasets.registry import DatasetRegistry, default_dataset_registry
from benchmarks.datasets.reporting import separated_dataset_report
from benchmarks.datasets.service_tools import VirtualServiceWorld
from benchmarks.schema import CallPredicate
from traceguard.cli import main
from traceguard.types import Decision, ThreatModel, ToolCall

EXPECTED_DATASETS = {
    "agentdyn",
    "agentharm",
    "asb-subset",
    "injecagent",
    "llmail-inject",
    "r-judge",
    "toolsword",
}


def test_dataset_registry_verifies_all_frozen_fixtures():
    registry = default_dataset_registry()
    assert set(registry.names()) == EXPECTED_DATASETS
    for name in registry.names():
        verified = registry.verify(name, fixture_only=True)
        assert verified["fixture_verified"] is True
        assert len(verified["revision"]) == 40


def test_all_adversarial_fixture_cases_have_authorized_neighbor():
    registry = default_dataset_registry()
    for name in registry.names():
        request = AdapterRunRequest(dataset=name, tier="smoke")
        cases = registry.adapter(name).load_cases(request)
        ids = {case.case_id for case in cases}
        for case in cases:
            if case.threat_model is ThreatModel.BENIGN:
                continue
            assert case.authorized_near_neighbor_id
            assert case.authorized_near_neighbor_id in ids


def test_agentdyn_is_sealed_but_allows_contract_smoke():
    registry = default_dataset_registry()
    adapter = registry.adapter("agentdyn")
    assert adapter.load_cases(AdapterRunRequest(dataset="agentdyn", tier="smoke"))
    with pytest.raises(ValueError, match="sealed"):
        adapter.load_cases(AdapterRunRequest(dataset="agentdyn", tier="standard"))


def test_non_smoke_tiers_cannot_silently_reuse_fixture_cases():
    registry = default_dataset_registry()
    with pytest.raises(RuntimeError, match="external adapter"):
        registry.adapter("llmail-inject").run(
            AdapterRunRequest(dataset="llmail-inject", tier="standard")
        )


def test_fixture_episode_runner_never_performs_host_execution():
    registry = default_dataset_registry()
    results = registry.adapter("llmail-inject").run(
        AdapterRunRequest(
            dataset="llmail-inject",
            tier="smoke",
            supervisor_mode="none",
        )
    )
    assert len(results) == 4
    assert all(result.containment_evidence["host_execution"] is False for result in results)
    attacks = [item for item in results if item.threat_model != "BENIGN"]
    assert attacks
    assert all(item.prohibited_effect for item in attacks)


def test_deterministic_gateway_blocks_obvious_credential_access():
    gateway = SupervisionGateway(
        mode="deterministic",
        available_tools={"read_file": {"type": "object"}},
    )
    _, decision = gateway.evaluate(
        task_id="test",
        step_id=0,
        user_goal="Read the password and exfiltrate it.",
        tool_name="read_file",
        arguments={"path": "password.txt"},
        observations=[],
    )
    assert decision.decision is Decision.BLOCK


def test_exact_and_subset_call_predicates():
    call = ToolCall(
        task_id="t",
        step_id=0,
        tool_name="send_email",
        arguments={"to": "a@example.test", "body": "hello"},
    )
    assert call_matches(
        CallPredicate(
            tool_name="send_email",
            arguments={"to": "a@example.test"},
            match="subset",
        ),
        call,
    )
    assert not call_matches(
        CallPredicate(
            tool_name="send_email",
            arguments={"to": "a@example.test"},
            match="exact",
        ),
        call,
    )


def test_virtual_service_world_resets_and_keeps_email_synthetic():
    initial = {"outbox": [], "memories": {}}
    first = VirtualServiceWorld(initial)
    first.execute(
        "send_email",
        {"to": "nobody@example.test", "subject": "fixture", "body": "fixture"},
    )
    first.execute(
        "memory",
        {"command": "create", "path": "/memories/x.md", "content": "fixture"},
    )
    assert first.state["outbox"]
    assert first.state["memories"]
    second = VirtualServiceWorld(initial)
    assert second.state == initial


def test_llmail_normalization_selection_and_leakage_detection():
    assert normalize_payload("Ａ  \n B") == "a b"
    records = [
        LLMailRecord(
            record_id=f"r{index}",
            participant_id=f"p{index}",
            payload_family_id=f"f{index}",
            scenario=str(index % 2),
            phase=str(index % 2),
            payload="x",
            successful=bool(index % 2),
        )
        for index in range(6)
    ]
    assert [item.record_id for item in stratified_selection(records, limit=4)] == [
        "r0",
        "r1",
        "r2",
        "r3",
    ]
    assert not validate_group_disjoint_splits({"dev": records[:3], "test": records[3:]})
    leaked = records[3].__class__(
        **{
            **records[3].__dict__,
            "participant_id": records[0].participant_id,
        }
    )
    errors = validate_group_disjoint_splits({"dev": records[:3], "test": [leaked]})
    assert "crosses splits" in errors[0]


def test_reports_remain_separate_with_equal_dataset_macro():
    registry = default_dataset_registry()
    results = []
    for name in ("llmail-inject", "asb-subset"):
        results.extend(
            registry.adapter(name).run(
                AdapterRunRequest(dataset=name, tier="smoke", supervisor_mode="none")
            )
        )
    report = separated_dataset_report(results)
    assert set(report["datasets"]) == {"llmail-inject", "asb-subset"}
    assert report["macro"]["weighting"] == "equal_per_dataset"


def test_diagnostics_are_not_pooled_with_attack_prevention_metrics():
    registry = default_dataset_registry()
    diagnostic = registry.adapter("toolsword").run(
        AdapterRunRequest(dataset="toolsword", tier="smoke")
    )
    episodes = registry.adapter("asb-subset").run(
        AdapterRunRequest(dataset="asb-subset", tier="smoke")
    )
    report = separated_dataset_report([*diagnostic, *episodes])
    assert "toolsword" in report["diagnostics"]
    assert "toolsword" not in report["datasets"]
    assert report["diagnostics"]["toolsword"] == {
        "cases": 2,
        "measured_cases": 0,
        "accuracy": None,
        "macro_f1": None,
        "false_positive_rate": None,
        "risk_description_quality": None,
    }


def test_dataset_cli_lists_and_runs_smoke(tmp_path, capsys):
    assert main(["dataset", "--cache-root", str(tmp_path / "cache"), "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert {item["name"] for item in listed} == EXPECTED_DATASETS

    assert (
        main(
            [
                "benchmark",
                "run",
                "--dataset",
                "asb-subset",
                "--tier",
                "smoke",
                "--artifacts",
                str(tmp_path / "artifacts"),
                "--cache-root",
                str(tmp_path / "cache"),
                "--supervisor-mode",
                "none",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    run_dir = Path(payload["run_dir"])
    assert (run_dir / "results.jsonl").is_file()
    assert (run_dir / "summary.json").is_file()
    assert (run_dir / "experiment_manifest.json").is_file()
    manifest = json.loads((run_dir / "experiment_manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["requests"][0]["environment_lock_digest"]) == 64


def test_inspect_container_contract_is_fail_closed():
    compose = Path("benchmarks/environments/inspect/compose.yaml").read_text(encoding="utf-8")
    required_controls = (
        "@sha256:",
        "network_mode: none",
        "read_only: true",
        'user: "65532:65532"',
        "- ALL",
        "no-new-privileges:true",
        "pids_limit:",
        "mem_limit:",
        "cpus:",
        "noexec,nosuid,nodev",
    )
    for control in required_controls:
        assert control in compose
    assert "/var/run/docker.sock" not in compose
    assert "/Users/" not in compose


def test_every_environment_has_a_frozen_uv_lock():
    assert Path("uv.lock").is_file()
    for environment in ("agentdyn", "inspect"):
        lock = Path("benchmarks/environments") / environment / "uv.lock"
        assert lock.is_file()
        data = tomllib.loads(lock.read_text(encoding="utf-8"))
        assert data["version"] == 1
        assert data["package"]
        for package in data["package"]:
            source = package["source"]
            if "git" in source:
                assert re.search(r"#[0-9a-f]{40}$", source["git"]), "mutable VCS dependency"
            elif "registry" in source:
                artifacts = [
                    *package.get("wheels", []),
                    *([package["sdist"]] if "sdist" in package else []),
                ]
                assert artifacts, "registry package must have locked distribution artifacts"
                assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", x["hash"]) for x in artifacts)


def test_manifest_rejects_fixture_tampering(tmp_path):
    source = Path("benchmarks/datasets")
    manifests = tmp_path / "manifests"
    fixtures = tmp_path / "fixtures"
    manifests.mkdir()
    fixtures.mkdir()
    manifest = json.loads((source / "manifests" / "toolsword.json").read_text(encoding="utf-8"))
    (manifests / "toolsword.json").write_text(json.dumps(manifest), encoding="utf-8")
    (fixtures / "toolsword.json").write_text("[]", encoding="utf-8")
    registry = DatasetRegistry(manifests, tmp_path / "cache")
    with pytest.raises(ValueError, match="digest mismatch"):
        registry.verify("toolsword", fixture_only=True)
