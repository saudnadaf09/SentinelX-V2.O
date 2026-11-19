"""Request-ID, body-size limit and security-header middleware (pure ASGI)."""
from __future__ import annotations

import json
import uuid

from .logging import request_id_var


class RequestContextMiddleware:
    """Assigns a request ID, rejects oversized bodies, adds security headers."""

    def __init__(self, app, max_body_bytes: int):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        rid = headers.get("x-request-id", "")
        rid = rid if rid.replace("-", "").isalnum() and 8 <= len(rid) <= 64 else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        token = request_id_var.set(rid)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers", []))
                hdrs += [(b"x-request-id", rid.encode()), (b"x-content-type-options", b"nosniff"),
                         (b"x-frame-options", b"DENY"), (b"referrer-policy", b"no-referrer"),
                         (b"cache-control", b"no-store")]
                message["headers"] = hdrs
            await send(message)

        try:
            cl = headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > self.max_body_bytes:
                body = json.dumps({"error": {"code": "payload_too_large", "message": "Request body too large",
                                             "request_id": rid}}).encode()
                await send_with_headers({"type": "http.response.start", "status": 413,
                                         "headers": [(b"content-type", b"application/json")]})
                await send_with_headers({"type": "http.response.body", "body": body})
                return

            received = 0

            async def limited_receive():
                nonlocal received
                msg = await receive()
                if msg["type"] == "http.request":
                    received += len(msg.get("body", b""))
                    if received > self.max_body_bytes:
                        raise ValueError("request body exceeds limit")  # aborts the request (clients that lie about Content-Length); nginx also caps bodies
                return msg

            await self.app(scope, limited_receive, send_with_headers)
        finally:
            request_id_var.reset(token)
