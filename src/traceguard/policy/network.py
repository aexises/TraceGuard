"""Structural URL authority and public-HTTPS execution without implicit redirects."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


class UnsafeDestination(ValueError):
    pass


@dataclass(frozen=True)
class Destination:
    scheme: str
    host: str
    port: int
    path: str
    query: str


def destination(url: str) -> Destination:
    if not isinstance(url, str) or re.search(r"[\x00-\x20\x7f\\]", url):
        raise UnsafeDestination("invalid URL characters")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
        if port == 0:
            raise UnsafeDestination("port zero is not an executable destination")
        if (
            parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or "%" in host
            or host.endswith(".")
        ):
            raise UnsafeDestination("unsupported URL authority")
        host = host.encode("idna").decode("ascii").lower()
        if ":" in host:
            ipaddress.IPv6Address(host)
        elif not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", host):
            raise UnsafeDestination("invalid hostname")
        path = parsed.path or "/"
        # Reject aliases instead of guessing how an upstream server decodes them.
        if re.search(r"%(?:2e|2f|5c|25)|%(?![0-9a-f]{2})", path, re.I):
            raise UnsafeDestination("encoded path alias")
        if any(part in {".", ".."} for part in unquote(path).split("/")):
            raise UnsafeDestination("dot path segments")
        return Destination(
            parsed.scheme,
            host,
            port or (443 if parsed.scheme == "https" else 80),
            path,
            parsed.query,
        )
    except (ValueError, UnicodeError) as exc:
        raise UnsafeDestination("invalid destination URL") from exc


def target_within_scope(scope: str, target: str) -> bool:
    """URL scopes match exact origins, path segment boundaries and query strings."""
    try:
        allowed, proposed = destination(scope), destination(target)
    except UnsafeDestination:
        return False
    return (
        (allowed.scheme, allowed.host, allowed.port)
        == (proposed.scheme, proposed.host, proposed.port)
        and (
            proposed.path == allowed.path
            or proposed.path.startswith(allowed.path.rstrip("/") + "/")
        )
        and proposed.query == allowed.query
    )


def public_addresses(host: str, port: int) -> tuple[str, ...]:
    addresses = tuple(
        dict.fromkeys(
            item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )
    )
    if not addresses:
        raise UnsafeDestination("destination has no addresses")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_unspecified
            or getattr(ip, "ipv4_mapped", None)
        ):
            raise UnsafeDestination("destination resolves to a non-public address")
    return addresses


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        # Connect to the validated IP; TLS still authenticates the original hostname.
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class PublicHTTPTransport:
    """Supported profile: public HTTPS, bounded responses, no proxies or redirects."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        json_body: dict | None,
        *,
        max_bytes: int = 1_048_576,
    ) -> bytes:
        target = destination(url)
        if target.scheme != "https":
            raise UnsafeDestination("the public HTTP executor requires HTTPS")
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise UnsafeDestination("unsupported HTTP method")
        prohibited = {
            "host",
            "connection",
            "transfer-encoding",
            "content-length",
            "proxy-authorization",
            "upgrade",
        }
        for name, value in headers.items():
            if (
                name.lower() in prohibited
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or re.search(r"[\x00-\x1f\x7f]", value)
            ):
                raise UnsafeDestination("unsafe HTTP header")
        addresses = public_addresses(target.host, target.port)
        body = json.dumps(json_body, allow_nan=False).encode() if json_body is not None else None
        if body and len(body) > 1_048_576:
            raise UnsafeDestination("request body exceeds limit")
        connection = PinnedHTTPSConnection(target.host, target.port, addresses[0], timeout=15)
        try:
            request_target = target.path + ("?" + target.query if target.query else "")
            connection.request(method, request_target, body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise UnsafeDestination(
                    "redirects are disabled; evaluate the new destination explicitly"
                )
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise UnsafeDestination("HTTP response exceeds limit")
            if response.status >= 400:
                raise OSError(f"upstream HTTP status {response.status}")
            return payload
        finally:
            connection.close()
