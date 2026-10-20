import json
import socket
import threading
import time
from contextlib import contextmanager

import pytest
from test_mtls_executor import client

from traceguard.isolation_fixture import prepare
from traceguard.mtls import BoundaryServer, PeerIdentities, tls_context


@contextmanager
def fixture_server(tmp_path, *, seconds=0.4, dispatch=None):
    fixture = prepare(tmp_path / "fixture")
    root = fixture["directories"]["authority"]
    effects = []

    def handler(*args):
        effects.append(args)
        return {"ok": True}

    server = BoundaryServer(
        ("127.0.0.1", 0),
        context=tls_context(
            root / "certificate.pem", root / "key.pem", root / "ca.pem", server=True
        ),
        identities=PeerIdentities(root / "peers.json"),
        dispatch=dispatch or handler,
        ingress_seconds=seconds,
        max_connections=6,
        max_peer_connections=2,
    )
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield fixture, server, effects
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def connect(fixture, server, role="agent"):
    directory = fixture["directories"][role]
    context = tls_context(
        directory / "certificate.pem", directory / "key.pem", directory / "ca.pem"
    )
    plain = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
    return context.wrap_socket(plain, server_hostname="localhost")


def test_unregistered_ca_valid_peer_is_rejected_before_sending_any_http_headers(tmp_path):
    with fixture_server(tmp_path) as (fixture, server, effects):
        started = time.monotonic()
        with connect(fixture, server, "unknown") as connection:
            assert b"403" in connection.recv(4096)
        assert time.monotonic() - started < 1
        assert not effects


@pytest.mark.parametrize("stage", ["headers", "body"])
def test_authorized_drip_hits_absolute_deadline_despite_regular_progress(tmp_path, stage):
    with fixture_server(tmp_path) as (fixture, server, effects):
        started = time.monotonic()
        with connect(fixture, server) as connection:
            connection.sendall(b"POST /fixture HTTP/1.0\r\n")
            if stage == "body":
                connection.sendall(b"Content-Length: 100\r\n\r\n")
            for _ in range(12):
                time.sleep(0.075)
                try:
                    connection.sendall(b" " if stage == "body" else b"X-Fixture: progress\r\n")
                except OSError:
                    break
            try:
                assert not connection.recv(4096)
            except OSError:
                pass
        # 0.4s configured absolute deadline plus bounded scheduling/TLS teardown tolerance.
        assert time.monotonic() - started < 1.1
        assert not effects
        assert client(fixture, "executor", "authority", server.server_port).request(
            "/fixture", {}
        ) == {"ok": True}


def test_plain_handshake_stalls_expire_and_release_all_slots(tmp_path):
    with fixture_server(tmp_path) as (fixture, server, effects):
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as plain:
            assert plain.recv(1) == b""
        assert time.monotonic() - started < 1
        assert not effects
        assert client(fixture, "agent", "authority", server.server_port).request(
            "/fixture", {}
        ) == {"ok": True}


def test_one_registered_peer_cannot_occupy_other_workloads_capacity(tmp_path):
    with fixture_server(tmp_path, seconds=1) as (fixture, server, effects):
        with connect(fixture, server) as first, connect(fixture, server) as second:
            first.sendall(b"POST /fixture HTTP/1.0\r\n")
            second.sendall(b"POST /fixture HTTP/1.0\r\n")
            with connect(fixture, server) as denied:
                assert b"403" in denied.recv(4096)
            assert client(fixture, "executor", "authority", server.server_port).request(
                "/fixture", {}
            ) == {"ok": True}
        assert len(effects) == 1


@pytest.mark.parametrize(
    "headers",
    [
        b"X-Fixture: " + b"x" * 4096 + b"\r\n",
        b"X-Fixture: x\r\n" * 66,
        (b"X-Fixture: " + b"x" * 4000 + b"\r\n") * 9,
    ],
)
def test_header_line_count_and_total_byte_limits_withhold_dispatch(tmp_path, headers):
    with fixture_server(tmp_path) as (fixture, server, effects):
        with connect(fixture, server) as connection:
            try:
                connection.sendall(
                    b"POST /fixture HTTP/1.0\r\n" + headers + b"Content-Length: 2\r\n\r\n{}"
                )
                connection.recv(4096)
            except OSError:
                pass
        assert not effects
        assert client(fixture, "executor", "authority", server.server_port).request(
            "/fixture", {}
        ) == {"ok": True}


def test_registry_revocation_during_ingress_is_checked_again_before_dispatch(tmp_path, monkeypatch):
    with fixture_server(tmp_path, seconds=1) as (fixture, server, effects):
        resolve = server.identities.resolve
        parsing = threading.Event()
        count = 0

        def observed(certificate):
            nonlocal count
            actor = resolve(certificate)
            count += 1
            if count == 2:
                parsing.set()
            return actor

        monkeypatch.setattr(server.identities, "resolve", observed)
        with connect(fixture, server) as connection:
            connection.sendall(b"POST /fixture HTTP/1.0\r\nContent-Length: 2\r\n\r\n{")
            assert parsing.wait(0.5)
            root = fixture["directories"]["authority"]
            records = json.loads((root / "peers.json").read_bytes())
            del records[fixture["fingerprints"]["agent"]]
            (root / "peers.json").write_text(json.dumps(records))
            connection.sendall(b"}")
            assert b"403" in connection.recv(4096)
        assert not effects


def test_ingress_timer_does_not_classify_slow_post_dispatch_work_as_not_executed(tmp_path):
    effects = []

    def slow(*args):
        effects.append(args)
        time.sleep(0.6)
        return {"ok": True}

    with fixture_server(tmp_path, dispatch=slow) as (fixture, server, _):
        assert client(fixture, "agent", "authority", server.server_port).request(
            "/fixture", {}
        ) == {"ok": True}
    assert len(effects) == 1
