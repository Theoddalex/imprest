"""Entrypoint — runs the agentpay MCP server over stdio.

Thin, like the backend's main.py. All the wiring is in create_application().

Run:  python main.py
Or point any MCP client at:  {"command": "python", "args": ["main.py"]}
"""

from src.application import create_application

mcp = create_application()

if __name__ == "__main__":
    mcp.run()  # stdio transport by default
