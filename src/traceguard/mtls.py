"""Bounded mutually authenticated JSON transport for the isolated local profile."""

from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import threading
import time
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


class BoundaryServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, *, context, identities: PeerIdentities, dispatch):
        self.context, self.identities, self.dispatch = context, identities, dispatch
        self.slots = threading.BoundedSemaphore(16)
        self.rate_lock = threading.Lock()
        self.rates = {}
        super().__init__(address, BoundaryHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(5)
            with self.context.wrap_socket(request, server_side=True) as secure:
                super().process_request_thread(secure, client_address)
        except (ssl.SSLError, OSError):
            request.close()
        finally:
            self.slots.release()

    def admitted(self, actor: Actor) -> bool:
        with self.rate_lock:
            now = time.monotonic()
            self.rates = {key: value for key, value in self.rates.items() if value[0] > now - 60}
            key = (actor.subject, actor.service_key_id)
            if key not in self.rates and len(self.rates) >= 1024:
                return False
            start, count = self.rates.get(key, (now, 0))
            self.rates[key] = (start, count + 1)
            return count < 120


class BoundaryHandler(BaseHTTPRequestHandler):
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
            if not self.server.admitted(actor):
                return self.reply(429, {"detail": "workload request budget exhausted"})
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
