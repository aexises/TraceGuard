"""Exercise readiness without sending or retrying a consequential request."""

import socket
import subprocess
import sys
import threading

from traceguard.validation.isolation_canary import _READINESS_PROBE


def test_readiness_waits_for_delayed_listener_without_sending_request():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        received = []

        def start_later():
            threading.Event().wait(0.2)
            listener.listen()
            listener.settimeout(3)
            with listener.accept()[0] as connection:
                connection.settimeout(3)
                received.append(connection.recv(1))

        worker = threading.Thread(target=start_later)
        worker.start()
        result = subprocess.run(
            [sys.executable, "-c", _READINESS_PROBE, str(port), "2"],
            capture_output=True,
            timeout=4,
        )
        worker.join(timeout=4)
        assert not worker.is_alive()
        assert result.returncode == 0, result.stderr
        assert received == [b""]


def test_readiness_fails_within_budget_when_listener_never_starts():
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        result = subprocess.run(
            [sys.executable, "-c", _READINESS_PROBE, str(reserved.getsockname()[1]), "0.2"],
            capture_output=True,
            timeout=2,
        )
    assert result.returncode != 0
    assert b"service listener readiness deadline exceeded" in result.stderr
