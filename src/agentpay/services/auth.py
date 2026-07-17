"""Authentication: API key -> agent identity.

Keys are configured via the AGENTPAY_API_KEYS env var ("key:agent_id,key2:id2")
so secrets stay out of policy.yaml and drop cleanly into k8s secrets.

The resolved identity travels in a contextvar, so the MCP tools (which have no
request object) can ask "who is calling?" regardless of transport:
  - streamable-http: AuthMiddleware validates the Bearer key per request
  - stdio: the OS is the boundary; identity comes from settings.agent_id
"""

from __future__ import annotations

from contextvars import ContextVar

# Identity of the caller for the current request. Default for stdio/local use.
current_agent_id: ContextVar[str] = ContextVar("current_agent_id", default="local")


def parse_api_keys(raw: str) -> dict[str, str]:
    """Parse "key1:agent-a,key2:agent-b" into {key: agent_id}."""
    keys: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            raise ValueError(
                f"malformed API key entry {pair!r} — expected 'key:agent_id'"
            )
        key, agent_id = pair.split(":", 1)
        if not key or not agent_id:
            raise ValueError(f"malformed API key entry {pair!r}")
        keys[key.strip()] = agent_id.strip()
    return keys


class AuthMiddleware:
    """ASGI middleware: reject HTTP requests without a valid Bearer API key.

    Runs BEFORE the MCP app sees the request — an unauthenticated caller never
    reaches any tool. On success, stashes the caller's agent_id in the
    contextvar for the tools to read.
    """

    def __init__(self, app, api_keys: dict[str, str]) -> None:
        self.app = app
        self.api_keys = api_keys

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        agent_id = self.api_keys.get(token)

        if agent_id is None:
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"error": "missing or invalid API key"}',
                }
            )
            return

        current_agent_id.set(agent_id)
        await self.app(scope, receive, send)
