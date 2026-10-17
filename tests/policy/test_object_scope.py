import pytest

from traceguard.policy.authorization import check_authority
from traceguard.types import Decision, TaskAuthority, ToolCall


def call(tool, **arguments):
    return ToolCall(task_id="scope", step_id=0, tool_name=tool, arguments=arguments)


@pytest.mark.parametrize(
    "tool,field,goal",
    [
        ("delete_email", "email_id", "Delete email 123"),
        ("delete_file", "file_id", "Delete file 123"),
        ("get_file", "file_id", "Read the file"),
        ("get_webpage", "url", "Read the website"),
    ],
)
def test_tool_family_or_read_label_never_grants_resource_scope(tool, field, goal):
    denied = check_authority(goal, call(tool, **{field: "unapproved"}), [])
    assert denied is not None and denied.decision is Decision.ESCALATE


def test_exact_object_scope_allows_authorized_delete_and_blocks_substitution():
    scope = TaskAuthority(
        allowed_tools=["delete_email"], resource_values={"delete_email": {"email_id": ["123"]}}
    )
    assert (
        check_authority(
            "Delete the approved email", call("delete_email", email_id="123"), [], scope
        )
        is None
    )
    assert (
        check_authority(
            "Delete the approved email", call("delete_email", email_id="999"), [], scope
        ).decision
        is Decision.BLOCK
    )


def test_read_network_query_is_an_outbound_effect():
    scope = TaskAuthority(
        resource_values={"get_webpage": {"url": ["https://public.example.test/"]}}
    )
    assert (
        check_authority("Read", call("get_webpage", url="https://public.example.test/"), [], scope)
        is None
    )
    assert (
        check_authority(
            "Read", call("get_webpage", url="https://public.example.test/?data=canary"), [], scope
        ).decision
        is Decision.BLOCK
    )


def test_new_object_id_field_cannot_hide_behind_existing_tool_name():
    denied = check_authority(
        "Read",
        call("get_webpage", url="https://example.test/", credential_id="private"),
        [],
        TaskAuthority(argument_values={"get_webpage": {"url": "https://example.test/"}}),
    )
    assert denied is not None and denied.decision is Decision.ESCALATE


def test_sensitive_read_requires_explicit_tool_grant():
    assert (
        check_authority("Read", call("get_credit_card_details"), []).decision is Decision.ESCALATE
    )
    assert (
        check_authority(
            "Read",
            call("get_credit_card_details"),
            [],
            TaskAuthority(allowed_tools=["get_credit_card_details"]),
        )
        is None
    )


@pytest.mark.parametrize("actual", [True, 1.0, "1", None])
def test_resource_scope_does_not_use_python_coercive_equality(actual):
    scope = TaskAuthority(resource_values={"delete_email": {"email_id": [1]}})
    denied = check_authority("Delete", call("delete_email", email_id=actual), [], scope)
    assert denied is not None and denied.decision is Decision.BLOCK
