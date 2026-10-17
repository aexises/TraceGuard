from types import SimpleNamespace

import pytest

from traceguard.release_gate import ArtifactStore, GuardedProvider, ReleaseGate


def test_artifact_remains_private_until_explicit_label_and_sink_approval(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "report.txt").write_text("Safe report")
    store = ArtifactStore(tmp_path / "artifacts")
    identity = store.ingest(source, ["report.txt"])
    assert store.manifest(identity)["status"] == "quarantined"
    assert not list(store.released.iterdir())
    gate = ReleaseGate(frozenset({"artifact"}))
    with pytest.raises(PermissionError):
        store.release(identity, gate)
    destination = store.release(identity, gate, label="public")
    assert (destination / "report.txt").read_text() == "Safe report"
    assert store.manifest(identity)["status"] == "released"


@pytest.mark.parametrize("condition", ["rejected", "changed", "credential", "protected"])
def test_release_withholds_rejected_tampered_or_protected_artifacts(tmp_path, condition):
    source = tmp_path / "source"
    source.mkdir()
    content = {
        "credential": '{"password":"HARMLESS_CANARY"}',
        "protected": "DECLARED_PRIVATE_CANARY",
    }.get(condition, "Safe report")
    (source / "report.txt").write_text(content)
    store = ArtifactStore(tmp_path / "artifacts")
    identity = store.ingest(source, ["report.txt"])
    if condition == "rejected":
        store.reject(identity)
    elif condition == "changed":
        path = store.private / identity / "files/report.txt"
        path.chmod(0o600)
        path.write_text("modified after inspection")
    gate = ReleaseGate(frozenset({"artifact"}), prohibited_literals=("DECLARED_PRIVATE_CANARY",))
    with pytest.raises(PermissionError):
        store.release(identity, gate, label="public")
    assert not list(store.released.iterdir())


def test_provider_release_is_checked_before_any_external_call():
    calls = []
    provider = SimpleNamespace(evaluate=lambda request: calls.append(request))
    gate = ReleaseGate(frozenset({"model_provider"}), prohibited_literals=("HARMLESS_CANARY",))
    guarded = GuardedProvider(provider, gate, input_label="public")
    request = SimpleNamespace(model_dump_json=lambda: '{"observation":"HARMLESS_CANARY"}')
    with pytest.raises(PermissionError):
        guarded.evaluate(request)
    assert calls == []
    request.model_dump_json = lambda: '{"observation":"Safe public data"}'
    guarded.evaluate(request)
    assert len(calls) == 1


def test_final_answer_requires_independent_sink_authority_and_bounded_content():
    gate = ReleaseGate(frozenset({"final_answer"}), max_bytes=32)
    assert gate.authorize("final_answer", b"Approved public answer", label="public")
    for sink, content, label in [
        ("model_provider", b"text", "public"),
        ("final_answer", b"text", "confidential"),
        ("final_answer", b"x" * 33, "public"),
    ]:
        with pytest.raises(PermissionError):
            gate.authorize(sink, content, label=label)


def test_strict_product_requires_answer_release_and_automatically_guards_model_input(tmp_path):
    from traceguard.security import SecuredTools
    from traceguard.supervisor.llm import QwenSupervisor
    from traceguard.tools.registry import default_registry
    from traceguard.types import TaskAuthority, ToolCall

    calls = []
    provider = SimpleNamespace(evaluate=lambda request: calls.append(request))
    boundary = SecuredTools(
        default_registry(tmp_path, tmp_path / "artifacts"),
        TaskAuthority(allowed_tools=["calculator"]),
        task_id="task",
        supervisor=QwenSupervisor(provider=provider),
    )
    result = boundary.execute_call(
        "Calculate",
        ToolCall(
            task_id="task", step_id=0, tool_name="calculator", arguments={"expression": "2+2"}
        ),
        [],
    )
    assert result.trace.episode_outcome == "ESCALATE"
    assert calls == []
    with pytest.raises(PermissionError):
        boundary.release_answer("Not yet approved")
