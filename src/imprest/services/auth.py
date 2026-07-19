"""Authentication: API key -> agent identity.

Keys are configured via the IMPREST_API_KEYS env var ("key:agent_id,key2:id2")
so secrets stay out of policy.yaml and drop cleanly into k8s secrets.

The resolved identity travels in a contextvar, so the MCP tools (which have no
request object) can ask "who is calling?" regardless of transport:
  - streamable-http: AuthMiddleware validates the Bearer key per request
  - stdio: the OS is the boundary; identity comes from settings.agent_id
"""

from __future__ import annotations

import hmac
from contextvars import ContextVar

# Identity of the caller for the current request. Default for stdio/local use.
current_agent_id: ContextVar[str] = ContextVar("current_agent_id", default="local")

# Whether the caller may resolve pending approvals. Admins are humans (operators),
# never agents — an agent must not be able to sign off its own needs_approval
# payment. Over HTTP this is granted by a separate admin key; over stdio the
# local operator owns the box, so it defaults on there (see main.py).
current_is_admin: ContextVar[bool] = ContextVar("current_is_admin", default=False)


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

    def __init__(self, app, api_keys: dict[str, str],
                 admin_keys: dict[str, str] | None = None) -> None:
        self.app = app
        self.api_keys = api_keys
        self.admin_keys = admin_keys or {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        resolved = self._resolve(token)

        if resolved is None:
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

        agent_id, is_admin = resolved
        current_agent_id.set(agent_id)
        current_is_admin.set(is_admin)
        await self.app(scope, receive, send)

    def _resolve(self, token: str) -> tuple[str, bool] | None:
        """Return (identity, is_admin) for a token, comparing in constant time.

        Admin keys are checked as well as agent keys; a token matching an admin
        key yields is_admin=True. A plain dict lookup leaks key length/prefix via
        timing; compare_digest against each known key does not. The key set is
        small, so O(n) is fine.
        """
        if not token:
            return None
        match: tuple[str, bool] | None = None
        for key, admin_id in self.admin_keys.items():
            if hmac.compare_digest(key, token):
                match = (admin_id, True)
        for key, agent_id in self.api_keys.items():
            if hmac.compare_digest(key, token):
                match = (agent_id, False)
        return match
