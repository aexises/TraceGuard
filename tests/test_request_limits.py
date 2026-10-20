import asyncio

import pytest
from test_grant_api import post

from traceguard.control.admission import RequestLimits
from traceguard.control.api import create_app, token_resolver
from traceguard.control.models import ActionRequest, Actor, Role
from traceguard.control.service import ControlPlane


def test_public_arguments_reject_depth_bytes_and_nonfinite_numbers():
    for value in [{"text": "x" * 70_000}, {"amount": float("nan")}, {"items": list(range(5000))}]:
        with pytest.raises(ValueError):
            ActionRequest(
                tenant_id="tenant",
                idempotency_key="test-key",
                kind="tool",
                operation="test",
                arguments=value,
            )


def test_api_admission_rejects_large_and_deep_json_before_mutating_state():
    agent = Actor(subject="agent", roles={Role.AGENT}, tenant_ids={"tenant"}, service_key_id="key")
    plane = ControlPlane(b"test-only-seed" + b"x" * 32)
    app = create_app(plane, token_resolver({"token": agent}))
    assert post(app, "/v1/actions/evaluate", {"text": "x" * 1_048_577}, "token")[0] == 413
    nested = {}
    for _ in range(40):
        nested = {"nested": nested}
    assert post(app, "/v1/actions/evaluate", nested, "token")[0] == 400
    assert not plane._audits


def test_rate_and_concurrency_budgets_withhold_before_application_dispatch():
    calls = []
    agent = Actor(subject="agent", roles={Role.AGENT}, tenant_ids={"tenant"}, service_key_id="key")

    async def application(scope, receive, send):
        calls.append(scope)
        await RequestLimits.reject(send, 200, "ok")

    limiter = RequestLimits(application, identity=lambda _: agent, requests_per_minute=1)

    async def run():
        output = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            output.append(message)

        scope = {"type": "http", "headers": []}
        await limiter(scope, receive, send)
        await limiter(scope, receive, send)
        limiter.inflight = limiter.max_inflight
        await limiter(scope, receive, send)
        return [event["status"] for event in output if event["type"] == "http.response.start"]

    assert asyncio.run(run()) == [200, 429, 429]
    assert len(calls) == 1
