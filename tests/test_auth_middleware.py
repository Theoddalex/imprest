"""Tests for the AuthMiddleware ASGI 401 door and identity propagation."""

from __future__ import annotations

import asyncio

from imprest.services.auth import (
    AuthMiddleware,
    current_agent_id,
    current_is_admin,
)

KEYS = {"sk-good": "support-bot"}
ADMIN_KEYS = {"sk-admin": "ops"}


def drive(middleware, headers, admin_keys=None):
    """Run the middleware as an ASGI callable; return (status, identity, sent).

    Also captures the resolved admin flag on `drive.last_is_admin` so admin
    tests can assert propagation without changing every existing call site.
    """
    seen = {}

    async def inner_app(scope, receive, send):
        seen["identity"] = current_agent_id.get()
        seen["is_admin"] = current_is_admin.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
    }
    token = current_is_admin.set(False)  # isolate from any leaked state
    try:
        mw = AuthMiddleware(inner_app, KEYS, admin_keys)
        asyncio.run(mw(scope, receive, send))
    finally:
        current_is_admin.reset(token)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    drive.last_is_admin = seen.get("is_admin")
    return status, seen.get("identity"), sent


def test_missing_header_gets_401_and_never_reaches_app():
    status, identity, sent = drive(AuthMiddleware, {})
    assert status == 401
    assert identity is None  # inner app never ran
    # advertises the scheme
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert any(h[0] == b"www-authenticate" for h in start["headers"])


def test_wrong_key_gets_401():
    status, identity, _ = drive(AuthMiddleware, {"authorization": "Bearer sk-nope"})
    assert status == 401
    assert identity is None


def test_valid_key_reaches_app_with_identity_set():
    status, identity, _ = drive(AuthMiddleware, {"authorization": "Bearer sk-good"})
    assert status == 200
    assert identity == "support-bot"


def test_basic_scheme_is_rejected():
    status, _, _ = drive(AuthMiddleware, {"authorization": "Basic sk-good"})
    assert status == 401


def test_agent_key_resolves_with_is_admin_false():
    status, identity, _ = drive(
        AuthMiddleware, {"authorization": "Bearer sk-good"}, admin_keys=ADMIN_KEYS
    )
    assert status == 200 and identity == "support-bot"
    assert drive.last_is_admin is False


def test_admin_key_resolves_with_is_admin_true():
    status, identity, _ = drive(
        AuthMiddleware, {"authorization": "Bearer sk-admin"}, admin_keys=ADMIN_KEYS
    )
    assert status == 200 and identity == "ops"
    assert drive.last_is_admin is True


def test_same_token_in_both_maps_resolves_to_agent_non_admin():
    # documents the fail-safe precedence: a dual-registered key never escalates.
    # (main.py refuses to start with overlapping key sets; this pins _resolve.)
    status, identity, _ = drive(
        AuthMiddleware, {"authorization": "Bearer sk-good"},
        admin_keys={"sk-good": "ops"},
    )
    assert status == 200 and identity == "support-bot"
    assert drive.last_is_admin is False


def test_non_http_scope_passes_through():
    called = {}

    async def inner_app(scope, receive, send):
        called["ran"] = scope["type"]

    async def noop(*a):
        return {"type": "lifespan.startup"}

    mw = AuthMiddleware(inner_app, KEYS)
    asyncio.run(mw({"type": "lifespan"}, noop, noop))
    assert called["ran"] == "lifespan"  # not blocked by auth
