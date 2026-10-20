"""Bounded mutually authenticated JSON transport for the isolated local profile."""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from traceguard.control.models import Actor
from traceguard.control.service import AuthorizationError
from traceguard.control.storage import CapacityError
from traceguard.limits import validate_json


def tls_context(certificate: Path, key: Path, ca: Path, *, server: bool = False) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certificate, key)
    context.load_verify_locations(cafile=ca)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class PeerIdentities:
    def __init__(self, registry: Path):
        self.registry = registry

    def resolve(self, certificate_der: bytes) -> Actor:
        # The application-owned registry is mounted read-only; re-read it for revocation.
        raw = self.registry.read_bytes()
        if len(raw) > 65_536:
            raise AuthorizationError("identity registry exceeds budget")
        records = json.loads(raw)
        validate_json(records)
        fingerprint = hashlib.sha256(certificate_der).hexdigest()
        if fingerprint not in records:
            raise AuthorizationError("client certificate is not an authorized workload")
        return Actor.model_validate(records[fingerprint])


class MTLSClient:
    def __init__(self, base_url: str, context: ssl.SSLContext, server_fingerprint: str):
        target = urlsplit(base_url)
        if (
            target.scheme != "https"
            or not target.hostname
            or target.username is not None
            or target.password is not None
            or target.path not in {"", "/"}
            or target.query
        ):
            raise ValueError("a fixed HTTPS service origin is required")
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("client TLS verification cannot be disabled")
        if len(server_fingerprint) != 64:
            raise ValueError("pinned server certificate fingerprint is required")
        self.host, self.port = target.hostname, target.port or 443
        self.context, self.fingerprint = context, server_fingerprint

    def request(self, path: str, payload: dict) -> dict:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("fixed service path required")
        validate_json(payload, max_bytes=1_048_576, max_nodes=16_384, max_depth=32)
        body = json.dumps(payload, allow_nan=False).encode()
        connection = http.client.HTTPSConnection(
            self.host, self.port, context=self.context, timeout=5
        )
        try:
            connection.connect()
            peer = connection.sock.getpeercert(binary_form=True)
            if hashlib.sha256(peer).hexdigest() != self.fingerprint:
                raise AuthorizationError("service certificate does not match the pinned identity")
            connection.request("POST", path, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError("service response exceeds budget")
            result = json.loads(raw)
            validate_json(result, max_bytes=1_048_576, max_nodes=16_384, max_depth=32)
            if response.status != 200:
                raise AuthorizationError(f"service withheld request ({response.status})")
            return result
        finally:
            connection.close()


@dataclass
class Ingress:
    deadline: float
    connection: socket.socket
    actor: Actor | None = None
    complete: bool = False
    expired: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)
    timer: threading.Timer | None = None

    def expire(self):
        with self.lock:
            if not self.complete:
                self.expired = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def finish(self):
        with self.lock:
            if self.expired or time.monotonic() >= self.deadline:
                raise TimeoutError("absolute ingress deadline exceeded")
            self.complete = True
            self.timer.cancel()


class HeaderBudgetReader:
    def __init__(self, stream):
        self.stream, self.bytes, self.lines = stream, 0, 0

    def readline(self, limit=-1):
        data = self.stream.readline(min(4097, limit) if limit >= 0 else 4097)
        self.bytes += len(data)
        self.lines += 1
        if len(data) > 4096 or self.bytes > 32768 or self.lines > 65:
            raise ValueError("HTTP request-line/header budget exceeded")
        return data

    def read(self, length):
        return self.stream.read(length)

    def close(self):
        self.stream.close()


class BoundaryServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(
        self,
        address,
        *,
        context,
        identities: PeerIdentities,
        dispatch,
        ingress_seconds: float = 5,
        max_connections: int = 16,
        max_peer_connections: int = 4,
    ):
        if not 0 < ingress_seconds <= 5 or not 1 <= max_peer_connections < max_connections <= 64:
            raise ValueError("invalid bounded ingress configuration")
        self.context, self.identities, self.dispatch = context, identities, dispatch
        self.slots = threading.BoundedSemaphore(max_connections)
        self.handshakes = threading.BoundedSemaphore(min(4, max_connections))
        self.ingress_seconds, self.max_peer_connections = ingress_seconds, max_peer_connections
        self.rate_lock = threading.Lock()
        self.rates = {}
        self.handshake_rates = {}
        self.peers = {}
        self.sessions = {}
        super().__init__(address, BoundaryHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        with self.rate_lock:
            self.sessions[request] = Ingress(time.monotonic() + self.ingress_seconds, request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.rate_lock:
                self.sessions.pop(request, None)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        secure, peer, acquired = None, None, False
        with self.rate_lock:
            ingress = self.sessions[request]
        ingress.timer = threading.Timer(max(0, ingress.deadline - time.monotonic()), ingress.expire)
        ingress.timer.daemon = True
        ingress.timer.start()
        try:
            with self.rate_lock:
                if not self._budget(client_address[0], self.handshake_rates, 120):
                    return
            if not self.handshakes.acquire(blocking=False):
                return
            acquired = True
            request.settimeout(max(0.001, ingress.deadline - time.monotonic()))
            secure = self.context.wrap_socket(
                request, server_side=True, do_handshake_on_connect=False
            )
            with ingress.lock:
                ingress.connection = secure
                if ingress.expired or time.monotonic() >= ingress.deadline:
                    raise TimeoutError("absolute ingress deadline exceeded")
            secure.do_handshake()
            self.handshakes.release()
            acquired = False
            # Exact registered identity is mandatory before any HTTP parsing.
            actor = self.identities.resolve(secure.getpeercert(binary_form=True))
            key = (actor.subject, actor.service_key_id)
            with self.rate_lock:
                if self.peers.get(key, 0) >= self.max_peer_connections or not self._budget(
                    key, self.rates, 120
                ):
                    raise AuthorizationError("peer connection/request budget exhausted")
                self.peers[key] = self.peers.get(key, 0) + 1
                peer = key
                ingress.actor = actor
                self.sessions[secure] = ingress
            self.finish_request(secure, client_address)
        except AuthorizationError:
            if secure is not None:
                try:
                    secure.sendall(
                        b"HTTP/1.0 403 Forbidden\r\nContent-Length: 2\r\n"
                        b"Connection: close\r\n\r\n{}"
                    )
                except OSError:
                    pass
        except (ssl.SSLError, OSError, ValueError, KeyError, TypeError):
            pass
        finally:
            ingress.timer.cancel()
            if acquired:
                self.handshakes.release()
            if secure is not None:
                secure.close()
            request.close()
            with self.rate_lock:
                self.sessions.pop(request, None)
                self.sessions.pop(secure, None)
                if peer is not None:
                    self.peers[peer] -= 1
                    if not self.peers[peer]:
                        del self.peers[peer]
            self.slots.release()

    @staticmethod
    def _budget(key, rates, limit):
        now = time.monotonic()
        expired = [key for key, value in rates.items() if value[0] <= now - 60]
        for expired_key in expired:
            del rates[expired_key]
        if key not in rates and len(rates) >= 1024:
            return False
        start, count = rates.get(key, (now, 0))
        rates[key] = (start, count + 1)
        return count < limit


class BoundaryHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.rfile = HeaderBudgetReader(self.rfile)

    def log_message(self, *_):
        pass

    def reply(self, status: int, payload: dict):
        body = json.dumps(payload, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            actor = self.server.identities.resolve(self.connection.getpeercert(binary_form=True))
            lengths = self.headers.get_all("Content-Length") or []
            if (
                len(lengths) != 1
                or not lengths[0].isdigit()
                or self.headers.get("Transfer-Encoding") is not None
            ):
                return self.reply(400, {"detail": "one bounded content length is required"})
            length = int(lengths[0])
            if length > 1_048_576:
                return self.reply(413, {"detail": "request exceeds budget"})
            raw = self.rfile.read(length)
            if len(raw) != length:
                return self.reply(400, {"detail": "incomplete request"})
            payload = json.loads(raw)
            validate_json(payload, max_bytes=1_048_576, max_nodes=16_384, max_depth=32)
            self.server.sessions[self.connection].finish()
            # Registry revocation during slow ingress must take effect before dispatch.
            actor = self.server.identities.resolve(self.connection.getpeercert(binary_form=True))
            result = self.server.dispatch(actor, self.path, payload)
            return self.reply(200, result)
        except AuthorizationError:
            return self.reply(403, {"detail": "workload or action is not authorized"})
        except (ValueError, KeyError, TypeError, RecursionError):
            return self.reply(400, {"detail": "invalid request or service configuration"})
        except CapacityError:
            return self.reply(503, {"detail": "authority admission quota exhausted"})
        except Exception:
            return self.reply(503, {"detail": "execution unavailable or outcome unknown"})
