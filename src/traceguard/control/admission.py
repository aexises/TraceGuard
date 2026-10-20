"""ASGI request budgets: body/depth/time, concurrent work and credential request rate."""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque

from traceguard.control.service import AuthorizationError
from traceguard.limits import validate_json


class RequestLimits:
    def __init__(
        self,
        app,
        *,
        identity,
        max_body: int = 1_048_576,
        max_inflight: int = 16,
        requests_per_minute: int = 120,
        max_principals: int = 1024,
    ):
        self.app, self.identity = app, identity
        self.max_body, self.max_inflight = max_body, max_inflight
        self.requests_per_minute, self.max_principals = requests_per_minute, max_principals
        self.inflight = 0
        self.buckets = {}

    @staticmethod
    async def reject(send, status, detail):
        body = json.dumps({"detail": detail}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.inflight >= self.max_inflight:
            return await self.reject(send, 429, "concurrency budget exhausted")
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        try:
            actor = self.identity(headers.get(b"authorization", b"").decode("ascii"))
        except (AuthorizationError, UnicodeError):
            actor = None
        if actor is not None:
            now = time.monotonic()
            self.buckets = {
                key: value for key, value in self.buckets.items() if value and value[-1] > now - 60
            }
            key = (actor.subject, actor.service_key_id)
            if key not in self.buckets and len(self.buckets) >= self.max_principals:
                return await self.reject(send, 429, "credential admission budget exhausted")
            bucket = self.buckets.setdefault(key, deque())
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if len(bucket) >= self.requests_per_minute:
                return await self.reject(send, 429, "credential request budget exhausted")
            bucket.append(now)
        self.inflight += 1
        try:
            payload = bytearray()
            deadline = time.monotonic() + 5
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return await self.reject(send, 408, "request body timeout")
                try:
                    message = await asyncio.wait_for(receive(), remaining)
                except TimeoutError:
                    return await self.reject(send, 408, "request body timeout")
                if message["type"] == "http.disconnect":
                    return
                payload.extend(message.get("body", b""))
                if len(payload) > self.max_body:
                    return await self.reject(send, 413, "request body exceeds budget")
                if not message.get("more_body"):
                    break
            if payload:
                try:
                    validate_json(
                        json.loads(payload), max_bytes=self.max_body, max_nodes=16_384, max_depth=32
                    )
                except (ValueError, TypeError, RecursionError, UnicodeError):
                    return await self.reject(send, 400, "invalid or over-budget JSON")
            delivered = False

            async def buffered_receive():
                nonlocal delivered
                if delivered:
                    return await receive()
                delivered = True
                return {"type": "http.request", "body": bytes(payload), "more_body": False}

            await self.app(scope, buffered_receive, send)
        finally:
            self.inflight -= 1
