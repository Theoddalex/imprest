"""Console entrypoint — `agentmandate` on the command line (or `uvx agentmandate`).

Subcommands (operator CLI, see cli.py):
  agentmandate init      create policy.yaml + the agent's wallet, print the
                         funding address (the onboarding ceremony)
  agentmandate status    wallet, balances, policy limits, sends switch

With no subcommand the MCP server runs; transport comes from settings/.env:
  TRANSPORT=stdio            local: each MCP client spawns its own server;
                             the OS is the auth boundary, identity = AGENT_ID
  TRANSPORT=streamable-http  hosted: one server at http://HOST:PORT/mcp.
                             Requires AGENTMANDATE_API_KEYS ("key:agent-id,...");
                             refuses to start without them unless
                             ALLOW_ANONYMOUS=true is set explicitly.
"""

import logging
import sys

from agentmandate.application import create_application
from agentmandate.cli import run_command
from agentmandate.configs.base import settings
from agentmandate.services.auth import (
    AuthMiddleware,
    current_agent_id,
    current_is_admin,
    parse_api_keys,
)


def main() -> None:
    # Operator subcommands run and exit before any server (or logging that
    # would write to the MCP stdio channel) starts.
    if run_command(sys.argv[1:]):
        return

    # Logs go to STDERR — stdout is the MCP protocol channel over stdio, so
    # writing logs there would corrupt it. This lights up the agentmandate.* loggers.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    mcp = create_application()

    if settings.transport != "streamable-http":
        # stdio: local single-owner use; identity is configured, not proven. The
        # operator owns the box, so they're also the approver (is_admin).
        current_agent_id.set(settings.agent_id)
        current_is_admin.set(True)
        mcp.run()
        return

    # --- hosted mode ---
    api_keys = parse_api_keys(settings.agentmandate_api_keys)
    admin_keys = parse_api_keys(settings.agentmandate_admin_keys)

    overlap = set(api_keys) & set(admin_keys)
    if overlap:
        sys.exit(
            "agentmandate: the same key appears in both AGENTMANDATE_API_KEYS and "
            "AGENTMANDATE_ADMIN_KEYS. Keys must be disjoint — a shared key resolves to "
            "the non-admin agent identity, silently stripping approval rights. "
            "Give operators their own keys."
        )
    if not api_keys and not settings.allow_anonymous:
        sys.exit(
            "agentmandate: refusing to serve HTTP without authentication.\n"
            "This server fronts a wallet — an open endpoint means anyone who can\n"
            "reach it can spend the budget. Set AGENTMANDATE_API_KEYS='<key>:<agent-id>,...'\n"
            "or, for local experiments only, ALLOW_ANONYMOUS=true."
        )

    mcp.settings.host = settings.host
    mcp.settings.port = settings.port

    # Stateless HTTP: each request spawns its server task from the REQUEST's
    # async context. That is what lets AuthMiddleware's per-request identity
    # contextvar propagate into the tool — in stateful mode the tool runs in a
    # long-lived session task that captured identity once at session creation,
    # so a per-request Bearer key would be ignored (the identity bug we fixed).
    mcp.settings.stateless_http = True
    mcp.settings.json_response = True

    if api_keys:
        # Wrap the MCP ASGI app so unauthenticated requests die at the door.
        import uvicorn

        app = AuthMiddleware(mcp.streamable_http_app(), api_keys, admin_keys)
        uvicorn.run(app, host=settings.host, port=settings.port)
    else:
        mcp.run(transport="streamable-http")  # anonymous, explicitly allowed


if __name__ == "__main__":
    main()
