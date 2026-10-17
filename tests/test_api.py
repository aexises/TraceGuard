"""Exercise the shipped API factory and its HTTP authorization boundary."""

import json
import socket
import threading
import time
from contextlib import closing
from http.client import HTTPConnection

import pytest
import uvicorn

from traceguard.control.api import _development_app


@pytest.fixture
def configured_environment(monkeypatch):
    monkeypatch.setenv("TRACEGUARD_ALLOW_IN_MEMORY", "1")
    monkeypatch.setenv("TRACEGUARD_SIGNING_KEY", "test-signing-key-" + "a" * 32)
    monkeypatch.setenv("TRACEGUARD_DEV_TOKEN", "test-agent-token-" + "b" * 32)


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("TRACEGUARD_ALLOW_IN_MEMORY", ""),
        ("TRACEGUARD_ALLOW_IN_MEMORY", "0"),
        ("TRACEGUARD_SIGNING_KEY", ""),
        ("TRACEGUARD_SIGNING_KEY", "short"),
        ("TRACEGUARD_SIGNING_KEY", "development-key-change-me-32-bytes!"),
        ("TRACEGUARD_DEV_TOKEN", ""),
        ("TRACEGUARD_DEV_TOKEN", "development-token"),
    ],
)
def test_api_refuses_implicit_or_insecure_configuration(
    configured_environment, monkeypatch, variable, value
):
    monkeypatch.setenv(variable, value)
    with pytest.raises(RuntimeError):
        _development_app()


def test_http_boundary_requires_configured_token_and_fails_closed_without_policy(
    configured_environment,
):
    app = _development_app()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server.started
            with closing(HTTPConnection("127.0.0.1", port, timeout=3)) as connection:
                connection.request("GET", "/healthz")
                response = connection.getresponse()
                assert response.status == 200
                assert json.loads(response.read()) == {"status": "ok"}
                action = json.dumps(
                    {
                        "tenant_id": "tenant-a",
                        "idempotency_key": "http-boundary-test",
                        "kind": "http",
                        "operation": "GET",
                        "target": "https://example.test/",
                    }
                )
                for token, expected in [
                    (None, 401),
                    ("development-token", 401),
                    ("test-agent-token-" + "b" * 32, 200),
                ]:
                    headers = {"Content-Type": "application/json"}
                    if token:
                        headers["Authorization"] = "Bearer " + token
                    connection.request("POST", "/v1/actions/evaluate", action, headers)
                    response = connection.getresponse()
                    body = json.loads(response.read())
                    assert response.status == expected
                    if expected == 200:
                        assert body["decision"] == "BLOCK"
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            assert not thread.is_alive()
