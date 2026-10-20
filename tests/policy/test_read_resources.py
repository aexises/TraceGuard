from copy import deepcopy

import pytest

from benchmarks.datasets.gateway import SupervisionGateway
from traceguard.policy.kernel import CompiledAuthority
from traceguard.policy.read_resources import bind_read_schema
from traceguard.security import SecuredTools
from traceguard.tools.registry import default_registry
from traceguard.types import Decision, TaskAuthority, ToolCall


def decision(scope, schemas, call):
    return CompiledAuthority.compile(scope, schemas).evaluate("Read approved file", call, [])


@pytest.mark.parametrize("approved", [False, True])
def test_original_read_reproducer_has_common_kernel_gateway_and_facade_scope(tmp_path, approved):
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace/ordinary.csv").write_text("HARMLESS_READ_CANARY")
    tools = default_registry(tmp_path, tmp_path / "artifacts")
    scope = TaskAuthority(
        enforcement_mode="strict",
        allowed_tools=["read_file"],
        argument_values={"read_file": {"path": "workspace/ordinary.csv"}} if approved else {},
    )
    call = ToolCall(
        task_id="task",
        step_id=0,
        tool_name="read_file",
        arguments={"path": "workspace/ordinary.csv"},
    )
    kernel = decision(scope, tools.schemas(), call)
    gateway = SupervisionGateway(
        mode="deterministic", available_tools=tools.schemas(), task_authority=scope
    )
    normalized, result = gateway.evaluate(
        task_id="task",
        step_id=0,
        user_goal="Read approved file",
        tool_name="read_file",
        arguments=call.arguments,
        observations=[],
    )
    facade = SecuredTools(tools, scope, task_id="task").execute_call("Read approved file", call, [])
    assert (kernel.decision is Decision.ALLOW) == approved
    assert (result.decision is Decision.ALLOW) == approved
    assert (facade.observation is not None) == approved
    if approved:
        assert (
            tools.execute(normalized).content
            == facade.observation.content
            == "HARMLESS_READ_CANARY"
        )
        wrong = call.model_copy(update={"arguments": {"path": "other.csv"}})
        assert decision(scope, tools.schemas(), wrong).decision is not Decision.ALLOW


def test_implicit_document_corpus_requires_explicit_broad_resource_permission(tmp_path):
    tools = default_registry(tmp_path, tmp_path / "artifacts")
    call = ToolCall(
        task_id="task", step_id=0, tool_name="search_documents", arguments={"query": "hello"}
    )
    scope = TaskAuthority(enforcement_mode="strict", allowed_tools=["search_documents"])
    assert decision(scope, tools.schemas(), call).decision is not Decision.ALLOW
    scope.resource_values = {"search_documents": {"requested_resources": ["corpus:documents"]}}
    assert decision(scope, tools.schemas(), call).decision is Decision.ALLOW
    (tmp_path / "documents").mkdir()
    (tmp_path / "documents/fixture.txt").write_text("hello approved corpus")
    boundary = SecuredTools(tools, scope, task_id="task")
    assert "hello approved corpus" in boundary.execute_call("Search", call, []).observation.content


@pytest.mark.parametrize("selector", ["path", "file", "file_path"])
def test_familiar_tool_name_cannot_supply_its_own_resource_mapping(selector):
    schema = {
        "type": "object",
        "properties": {selector: {"type": "string"}},
        "required": [selector],
    }
    scope = TaskAuthority(
        enforcement_mode="strict",
        allowed_tools=["read_file"],
        argument_values={"read_file": {selector: "approved.txt"}},
    )
    call = ToolCall(
        task_id="task", step_id=0, tool_name="read_file", arguments={selector: "approved.txt"}
    )
    assert decision(scope, {"read_file": schema}, call).decision is not Decision.ALLOW


def test_bound_native_schema_enforces_actual_selector_and_reviewed_defaults():
    pytest.importorskip("inspect_ai")
    from inspect_ai.tool import list_files, read_file

    from benchmarks.datasets.inspect_integration import inspect_read_schema

    schema = inspect_read_schema(read_file(timeout=30))
    scope = TaskAuthority(
        enforcement_mode="strict",
        allowed_tools=["read_file"],
        argument_values={"read_file": {"file_path": "approved.txt"}},
    )
    call = ToolCall(
        task_id="task", step_id=0, tool_name="read_file", arguments={"file_path": "approved.txt"}
    )
    assert decision(scope, {"read_file": schema}, call).decision is Decision.ALLOW
    call.arguments = {"path": "approved.txt"}
    assert decision(scope, {"read_file": schema}, call).decision is not Decision.ALLOW
    changed = deepcopy(schema)
    changed["properties"]["alternate_root"] = {"type": "string"}
    with pytest.raises(ValueError, match="unreviewed"):
        bind_read_schema(changed, adapter_id="inspect-native-v1", tool_name="read_file")
    listing = inspect_read_schema(list_files(timeout=30))
    listing_scope = TaskAuthority(enforcement_mode="strict", allowed_tools=["list_files"])
    listing_call = ToolCall(task_id="task", step_id=0, tool_name="list_files", arguments={})
    assert (
        decision(listing_scope, {"list_files": listing}, listing_call).decision
        is not Decision.ALLOW
    )
    listing_scope.resource_values = {"list_files": {"path": ["."]}}
    assert decision(listing_scope, {"list_files": listing}, listing_call).decision is Decision.ALLOW
    changed = deepcopy(listing)
    changed["properties"]["path"]["default"] = "/unapproved"
    assert (
        decision(listing_scope, {"list_files": changed}, listing_call).decision
        is not Decision.ALLOW
    )
