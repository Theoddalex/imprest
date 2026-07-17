"""Console entrypoint — `agentpay` on the command line (or `uvx agentpay`).

Transport comes from settings/.env:
  TRANSPORT=stdio            local: each MCP client spawns its own server;
                             the OS is the auth boundary, identity = AGENT_ID
  TRANSPORT=streamable-http  hosted: one server at http://HOST:PORT/mcp.
                             Requires AGENTPAY_API_KEYS ("key:agent-id,...");
                             refuses to start without them unless
                             ALLOW_ANONYMOUS=true is set explicitly.
"""

import sys

from agentpay.application import create_application
from agentpay.configs.base import settings
from agentpay.services.auth import AuthMiddleware, current_agent_id, parse_api_keys


def main() -> None:
    mcp = create_application()

    if settings.transport != "streamable-http":
        # stdio: local single-owner use; identity is configured, not proven.
        current_agent_id.set(settings.agent_id)
        mcp.run()
        return

    # --- hosted mode ---
    api_keys = parse_api_keys(settings.agentpay_api_keys)
    if not api_keys and not settings.allow_anonymous:
        sys.exit(
            "agentpay: refusing to serve HTTP without authentication.\n"
            "This server fronts a wallet — an open endpoint means anyone who can\n"
            "reach it can spend the budget. Set AGENTPAY_API_KEYS='<key>:<agent-id>,...'\n"
            "or, for local experiments only, ALLOW_ANONYMOUS=true."
        )

    mcp.settings.host = settings.host
    mcp.settings.port = settings.port

    if api_keys:
        # Wrap the MCP ASGI app so unauthenticated requests die at the door.
        import uvicorn

        app = AuthMiddleware(mcp.streamable_http_app(), api_keys)
        uvicorn.run(app, host=settings.host, port=settings.port)
    else:
        mcp.run(transport="streamable-http")  # anonymous, explicitly allowed


if __name__ == "__main__":
    main()
