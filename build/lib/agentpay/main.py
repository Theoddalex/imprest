"""Console entrypoint — `agentpay` on the command line (or `uvx agentpay`).

Transport comes from settings/.env:
  TRANSPORT=stdio            local: each MCP client spawns its own server
  TRANSPORT=streamable-http  hosted: one server at http://HOST:PORT/mcp,
                             many clients connect (the org deployment)
"""

from agentpay.application import create_application
from agentpay.configs.base import settings


def main() -> None:
    mcp = create_application()
    if settings.transport == "streamable-http":
        # FastMCP reads host/port from its own settings; pass through ours.
        mcp.settings.host = settings.host
        mcp.settings.port = settings.port
        mcp.run(transport="streamable-http")
    else:
        mcp.run()  # stdio


if __name__ == "__main__":
    main()
