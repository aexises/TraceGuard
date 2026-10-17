import asyncio
import json
from urllib.parse import urlsplit

from traceguard.control.api import create_app, token_resolver
from traceguard.control.models import Actor, PolicyDraft, PolicyRule, Role, RuleMatch
from traceguard.control.service import ControlPlane
from traceguard.types import TaskAuthority


def post(app, path, body, token):
    async def request():
        sent, output = False, []
        parsed = urlsplit(path)

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": json.dumps(body).encode(), "more_body": False}

        async def send(event):
            output.append(event)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": parsed.path,
            "raw_path": parsed.path.encode(),
            "query_string": parsed.query.encode(),
            "root_path": "",
            "server": ("test", 443),
            "client": ("test", 1),
            "headers": [
                (b"content-type", b"application/json"),
                (b"authorization", f"Bearer {token}".encode()),
            ],
        }
        await app(scope, receive, send)
        status = next(event["status"] for event in output if event["type"] == "http.response.start")
        payload = b"".join(
            event.get("body", b"") for event in output if event["type"] == "http.response.body"
        )
        return status, json.loads(payload)

    return asyncio.run(request())


def test_http_grant_lifecycle_checks_roles_and_exact_action():
    def actor(name, role, key=None):
        return Actor(subject=name, roles={role}, service_key_id=key, tenant_ids={"tenant"})

    admin, approver = actor("admin", Role.ADMIN), actor("approver", Role.APPROVER)
    agent, executor = (
        actor("agent", Role.AGENT, "agent-key"),
        actor("executor", Role.EXECUTOR, "executor-key"),
    )
    plane = ControlPlane(b"test-only-signing-seed-" + b"x" * 32)
    policy = plane.create_draft(
        "tenant",
        admin,
        PolicyDraft(
            name="allow",
            rules=[
                PolicyRule(
                    name="allow email",
                    priority=1,
                    match=RuleMatch(kind="tool", operation="send_email"),
                    decision="ALLOW",
                    reason="scoped",
                )
            ],
        ),
    )
    plane.submit_policy("tenant", admin, policy.policy_id)
    plane.approve_policy("tenant", approver, policy.policy_id)
    app = create_app(plane, token_resolver({"admin": admin, "agent": agent, "executor": executor}))
    authority = TaskAuthority(
        enforcement_mode="strict",
        allowed_tools=["send_email"],
        argument_values={"send_email": {"to": "alice@example.test"}},
        generated_fields={"send_email": ["body"]},
    )
    registration = {
        "task_id": "task",
        "agent_subject": "agent",
        "service_key_id": "agent-key",
        "adapter_digest": "a" * 64,
        "authority": authority.model_dump(mode="json"),
        "tool_schemas": {
            "send_email": {
                "type": "object",
                "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                "required": ["to", "body"],
                "additionalProperties": False,
            }
        },
    }
    assert post(app, "/v1/tasks/register?tenant_id=tenant", registration, "agent")[0] == 403
    assert post(app, "/v1/tasks/register?tenant_id=tenant", registration, "admin")[0] == 200
    action = {
        "tenant_id": "tenant",
        "task_id": "task",
        "idempotency_key": "api-grant-test",
        "kind": "tool",
        "operation": "send_email",
        "arguments": {"to": "alice@example.test", "body": "Approved summary"},
    }
    status, grant = post(
        app, "/v1/execution/grants", {"action": action, "executor_audience": "executor"}, "agent"
    )
    assert status == 200
    assert (
        post(app, "/v1/execution/validate", {"action": action, "grant": grant}, "agent")[0] == 403
    )
    assert (
        post(app, "/v1/execution/validate", {"action": action, "grant": grant}, "executor")[0]
        == 200
    )
    changed = {**action, "arguments": {"to": "mallory@example.test", "body": "Approved summary"}}
    assert (
        post(app, "/v1/execution/validate", {"action": changed, "grant": grant}, "executor")[0]
        == 403
    )
