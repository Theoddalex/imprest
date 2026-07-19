"""agent-shop — a shopping agent that pays through imprest (stdio mode).

I'm a solo developer. I own the wallet, I set the limits, and I build this
agent. I do NOT run a server. When this script starts it SPAWNS imprest as a
child process, talks to it over stdin/stdout pipes, and that child dies when I
exit — the same way an editor spawns a language server.

Files that live alongside this script (the "operator" side, which I own):
  policy.yaml   the limits my agent cannot override        (I wrote these)
  wallet.key    the testnet key imprest guards            (auto-created)
  audit.db      append-only log of every attempt           (auto-created)
  .env          my config (LLM key, chain, safety switch)

My agent code (below) never imports the policy engine, never sees the key, and
can only ASK to pay via the request_payment tool. The guard decides ALLOW /
DENY / NEEDS_APPROVAL — and my agent cannot talk it out of a decision.

Run:  python shop_agent.py "buy the premium weather feed for 0.01 ETH"
"""

import asyncio
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI

HERE = Path(__file__).parent
load_dotenv(HERE / ".env")

# imprest was installed into THIS venv with `pip install git+https://…/imprest`.
# Its console script sits next to the running python — a stdio MCP client
# launches it as a subprocess, so there is no server for me to run.
IMPREST_BIN = str(Path(sys.executable).parent / "imprest")

# The OPERATOR knobs, forwarded to the guard subprocess. My agent never sees
# these — they configure the process on the other side of the pipe.
GUARD_ENV = {
    **os.environ,                                   # inherit PATH, etc.
    "TRANSPORT": "stdio",
    "AGENT_ID": os.environ.get("AGENT_ID", "shop-agent"),
    "RPC_URL": os.environ["RPC_URL"],
    "CHAIN_ID": os.environ["CHAIN_ID"],
    "KEYSTORE_PATH": os.environ.get("KEYSTORE_PATH", "wallet.key"),
    "POLICY_PATH": os.environ.get("POLICY_PATH", "policy.yaml"),
    "AUDIT_DB_PATH": os.environ.get("AUDIT_DB_PATH", "audit.db"),
    "ENABLE_SENDS": os.environ.get("ENABLE_SENDS", "false"),
}

# My ENTIRE integration with imprest: "spawn this command with this config."
# That's it — no policy, no keys, no engine imported into my project.
IMPREST_SERVER = {
    "transport": "stdio",
    "command": IMPREST_BIN,
    "args": [],
    "env": GUARD_ENV,
    "cwd": str(HERE),          # so wallet.key / policy.yaml / audit.db resolve here
}

# The vendor the agent pays. REPLACE with an address YOU control before
# enabling sends — on mainnet, funds sent to a made-up address are gone.
VENDOR = "0x0000000000000000000000000000000000000000"


async def main() -> None:
    ask = sys.argv[1] if len(sys.argv) > 1 else "Buy the premium weather feed."

    # Connecting spawns imprest and asks it what tools it offers
    # (request_payment, request_approval, get_balance, …).
    client = MultiServerMCPClient({"imprest": IMPREST_SERVER})
    tools = await client.get_tools()

    agent = create_agent(
        model=ChatOpenAI(
            model=os.environ.get("MODEL", "google/gemini-2.5-flash"),
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url="https://openrouter.ai/api/v1",
            temperature=0,
            max_tokens=1024,
        ),
        tools=tools,
        system_prompt=(
            f"You are a shopping agent. The vendor's payment address is {VENDOR}. "
            "Use request_payment to pay for purchases. Report outcomes honestly, "
            "including any policy denials and their exact reasons."
        ),
    )

    result = await agent.ainvoke({"messages": [HumanMessage(ask)]})

    # Full trace: what the model asked for, and what the guard answered.
    for m in result["messages"]:
        kind = m.__class__.__name__
        if kind == "HumanMessage":
            print(f"\n[task]  {m.content}")
        elif kind == "AIMessage":
            for tc in getattr(m, "tool_calls", None) or []:
                print(f"\n[agent] calls {tc['name']} {tc['args']}")
            if m.content:
                print(f"\n[agent] {m.content}")
        elif kind == "ToolMessage":
            print(f"[guard] {m.content}")


if __name__ == "__main__":
    asyncio.run(main())
