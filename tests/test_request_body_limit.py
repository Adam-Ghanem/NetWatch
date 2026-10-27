"""Regression tests for early request body limits, including streamed requests."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from request_body_limit import RequestBodyLimitMiddleware


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestBodyLimitMiddleware, max_json_bytes=16, max_capture_bytes=32)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Security-Checked"] = "yes"
        return response

    @app.post("/api/echo")
    async def echo(request: Request):
        return {"size": len(await request.body())}

    @app.post("/api/traffic/offline/analyze")
    async def upload(request: Request):
        return {"size": len(await request.body())}

    @app.post("/outside-api")
    async def outside(request: Request):
        return {"size": len(await request.body())}

    return app


def test_declared_body_limit_accepts_boundary_and_rejects_larger_requests():
    with TestClient(_app()) as client:
        ok = client.post("/api/echo", content=b"a" * 16)
        over = client.post("/api/echo", content=b"a" * 17)
    assert ok.json() == {"size": 16}
    assert over.status_code == 413
    assert over.json() == {"detail": "Request body exceeds the size limit."}
    assert over.headers["x-security-checked"] == "yes"


def test_streaming_body_limit_rejects_chunked_requests_without_content_length():
    with TestClient(_app()) as client:
        ok = client.post("/api/echo", content=iter([b"a" * 8, b"b" * 8]))
        over = client.post("/api/echo", content=iter([b"a" * 8, b"b" * 9]))
    assert ok.json() == {"size": 16}
    assert over.status_code == 413
    assert over.headers["x-security-checked"] == "yes"


def test_capture_has_a_separate_bounded_budget():
    with TestClient(_app()) as client:
        ok = client.post("/api/traffic/offline/analyze", content=b"a" * 32)
        over = client.post("/api/traffic/offline/analyze", content=b"a" * 33)
        not_api = client.post("/outside-api", content=b"a" * 33)
    assert ok.json() == {"size": 32}
    assert over.status_code == 413
    assert not_api.json() == {"size": 33}


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"abc")],
        [(b"content-length", b"1"), (b"content-length", b"2")],
        [(b"content-length", b"1"), (b"content-length", b"1")],
        [(b"content-length", b"-2")],
        [(b"content-length", b"+2")],
        [(b"content-length", b"1_0")],
        [(b"content-length", b"9" * 5000)],
    ],
)
def test_rejects_ambiguous_and_invalid_content_length(headers):
    middleware = RequestBodyLimitMiddleware(_app(), max_json_bytes=16)

    async def invoke():
        messages = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        await middleware(
            {"type": "http", "method": "POST", "path": "/api/echo", "headers": headers},
            receive,
            send,
        )
        return messages

    assert asyncio.run(invoke())[0]["status"] == 400


def test_rejects_lied_content_length_by_counting_actual_bytes():
    calls = iter(
        [
            {"type": "http.request", "body": b"a" * 12, "more_body": True},
            {"type": "http.request", "body": b"b" * 7, "more_body": False},
        ]
    )
    received = []

    async def application(scope, receive, send):
        received.append(await receive())
        received.append(await receive())

    async def invoke():
        messages = []

        async def receive():
            return next(calls)

        async def send(message):
            messages.append(message)

        custom = RequestBodyLimitMiddleware(application, max_json_bytes=16)
        await custom(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/echo",
                "headers": [(b"content-length", b"10")],
            },
            receive,
            send,
        )
        return messages

    messages = asyncio.run(invoke())
    assert len(received) == 1
    assert messages[0]["status"] == 413
