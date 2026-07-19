"""Demo: a LangChain agent whose payments are gated by the imprest MCP server.

This is what a developer's setup looks like: their agent code knows NOTHING
about policies. It just gets a `request_payment` tool from the MCP server —
and the server (a separate process, holding the policy + keys) decides.

The demo walks three asks in one conversation:
  1. a small payment            -> policy allows it
  2. a big payment              -> policy BLOCKS it (per-transaction max)
  3. a medium payment           -> policy demands human approval
then prints the server's audit log — every attempt, and which rule fired.

Run (from the repo root):  python examples/demo_agent.py
"""

import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DEMO_RECIPIENT = "0xAAAA000000000000000000000000000000000001"

ASKS = [
    f"Pay 0.01 ETH to {DEMO_RECIPIENT} for the weather API subscription.",
    f"Now pay 0.5 ETH to {DEMO_RECIPIENT} for a premium data feed.",
    f"OK, try 0.03 ETH to {DEMO_RECIPIENT} instead.",
]


def get_model() -> ChatOpenAI:
    return ChatOpenAI(
        model=os.environ.get("MODEL", "google/gemini-2.5-flash"),
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
        temperature=0,
        max_tokens=1024,
    )


async def main() -> None:
    # The developer's ONLY integration step: point at the imprest server.
    client = MultiServerMCPClient(
        {
            "imprest": {
                "transport": "stdio",
                "command": sys.executable,          # this venv's python
                "args": [str(ROOT / "main.py")],
                "cwd": str(ROOT),                   # so policy.yaml/audit.db resolve
            }
        }
    )
    tools = await client.get_tools()
    print("tools from imprest server:", [t.name for t in tools], "\n")

    agent = create_agent(
        model=get_model(),
        tools=tools,
        system_prompt=(
            "You are a procurement agent. Use request_payment for any payment. "
            "Report the outcome honestly: if a payment was denied or needs human "
            "approval, say so and quote the policy's reason. Never retry a denied "
            "payment or try to work around it."
        ),
    )

    # One continuous conversation — the message list carries across asks.
    messages = []
    for ask in ASKS:
        print(f"═══ USER: {ask}")
        messages.append(HumanMessage(ask))
        result = await agent.ainvoke({"messages": messages})
        messages = result["messages"]
        print(f"AGENT: {messages[-1].content}\n")

    # Pull the audit log straight from the server — the compliance story.
    print("═══ AUDIT LOG (from the server, agent can't edit this) ═══")
    audit_tool = next(t for t in tools if t.name == "get_audit_log")
    raw = await audit_tool.ainvoke({})
    # MCP tools may return a JSON string or a list of content blocks.
    if isinstance(raw, list):
        raw = raw[0]["text"] if isinstance(raw[0], dict) else raw[0].text
    entries = json.loads(raw)["entries"]
    for e in entries:
        print(f"  {e['ts'][:19]}  {e['amount']:>5} ETH -> {e['decision']:<14} [{e['rule']}]")


if __name__ == "__main__":
    asyncio.run(main())
