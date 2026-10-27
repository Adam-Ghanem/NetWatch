"""Bound API request bodies before FastAPI parses untrusted input.

The guard checks both declared sizes and streamed bytes. It is deliberately
independent of endpoint dependencies: authentication and rate limiting happen
after body parsing in FastAPI, so they cannot protect the parser by themselves.
"""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from pcap_import import MAX_PCAP_BYTES

MAX_API_JSON_BYTES = 256 * 1024


class _BodyTooLarge(Exception):
    """Stop streaming an oversized request before it reaches its endpoint."""


class RequestBodyLimitMiddleware:
    """Cap API write requests, allowing a separate bounded PCAP upload budget."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_json_bytes: int = MAX_API_JSON_BYTES,
        max_capture_bytes: int = MAX_PCAP_BYTES,
    ) -> None:
        if max_json_bytes < 1 or max_capture_bytes < 1:
            raise ValueError("Request body limits must be positive.")
        self.app = app
        self.max_json_bytes = max_json_bytes
        self.max_capture_bytes = max_capture_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") not in {"POST", "PUT", "PATCH"}
            or not scope.get("path", "").startswith("/api/")
        ):
            await self.app(scope, receive, send)
            return

        offline_capture = scope["path"].startswith("/api/traffic/offline/")
        limit = self.max_capture_bytes if offline_capture else self.max_json_bytes
        too_large_detail = (
            "Capture input exceeds the safety limit."
            if offline_capture
            else "Request body exceeds the size limit."
        )
        declared_lengths = [
            value for name, value in scope.get("headers", []) if name.lower() == b"content-length"
        ]
        if declared_lengths:
            # Duplicate or non-decimal lengths are ambiguous at proxy boundaries.
            if (
                len(declared_lengths) != 1
                or not 1 <= len(declared_lengths[0]) <= 20
                or not declared_lengths[0].isdigit()
            ):
                await self._reject(scope, receive, send, 400, "Invalid Content-Length.")
                return
            if int(declared_lengths[0]) > limit:
                await self._reject(
                    scope, receive, send, 413, too_large_detail
                )
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _BodyTooLarge:
            if response_started:
                raise
            await self._reject(scope, receive, send, 413, too_large_detail)

    @staticmethod
    async def _reject(
        scope: Scope, receive: Receive, send: Send, status_code: int, detail: str
    ) -> None:
        await JSONResponse({"detail": detail}, status_code=status_code)(scope, receive, send)
