import pytest

from traceguard.policy.authorization import check_authority
from traceguard.policy.effects import email_effects
from traceguard.types import Decision, TaskAuthority, ToolCall


def proposed(**extra):
    return ToolCall(
        task_id="email",
        step_id=0,
        tool_name="send_email",
        arguments={
            "recipients": ["alice@example.com"],
            "subject": "Report",
            "body": "Approved text",
            **extra,
        },
    )


@pytest.mark.parametrize("field", ["cc", "bcc"])
def test_hidden_email_destinations_are_blocked(field):
    result = check_authority(
        "Send the report to alice@example.com", proposed(**{field: ["mallory@example.com"]}), []
    )
    assert result is not None and result.decision is Decision.BLOCK


def test_attachment_reference_requires_explicit_authority():
    call = proposed(attachments=[{"type": "file", "file_id": "private-file"}])
    denied = check_authority("Send the report to alice@example.com", call, [])
    assert denied is not None and denied.decision is Decision.ESCALATE
    scope = TaskAuthority(
        argument_values={"send_email": {"attachments": call.arguments["attachments"]}}
    )
    assert check_authority("Send the report to alice@example.com", call, [], scope) is None
    changed = proposed(attachments=[{"type": "file", "file_id": "other-file"}])
    assert (
        check_authority("Send the report to alice@example.com", changed, [], scope).decision
        is Decision.BLOCK
    )


def test_authorized_cc_and_empty_optional_sinks_preserve_utility():
    call = proposed(cc=["bob@example.com"], bcc=[], attachments=[])
    assert check_authority("Send to alice@example.com and bob@example.com", call, []) is None
    assert email_effects(call).recipients == (
        ("recipients", "alice@example.com"),
        ("cc", "bob@example.com"),
    )


def test_native_email_cannot_release_extra_destinations_or_attachments():
    from traceguard.supervisor.deterministic import DeterministicSupervisor

    gate = DeterministicSupervisor()
    gate.set_context(
        previous_calls=[],
        task_authority=TaskAuthority(
            allowed_tools=["send_email"],
            argument_values={"send_email": {"recipients": ["alice@example.com"]}},
        ),
    )
    for call in [
        proposed(cc=["mallory@example.com"]),
        proposed(bcc=["mallory@example.com"]),
        proposed(attachments=[{"type": "file", "file_id": "private-file"}]),
    ]:
        assert gate.evaluate("Send to alice@example.com", call, []).decision is not Decision.ALLOW
