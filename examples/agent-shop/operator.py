"""operator.py — the HUMAN side of the approval flow (no LLM involved).

When the agent's payment comes back `needs_approval`, it sits frozen in the
queue until a person rules on it. This script is that person's button:

  python operator.py list                 show what's waiting
  python operator.py approve <id> [note]  approve -> limits re-checked -> execute
  python operator.py reject  <id> [note]  reject, nothing moves

It talks to the same imprest guard over stdio; over stdio the local
operator is the admin (you own the box, you own the approve button).
"""

import asyncio
import json
import sys

from langchain_mcp_adapters.client import MultiServerMCPClient

from shop_agent import IMPREST_SERVER


async def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"

    client = MultiServerMCPClient({"imprest": IMPREST_SERVER})
    tools = {t.name: t for t in await client.get_tools()}

    if cmd == "list":
        out = await tools["list_pending_approvals"].ainvoke({})
    elif cmd in ("approve", "reject"):
        out = await tools["resolve_approval"].ainvoke({
            "payment_id": int(sys.argv[2]),
            "approve": cmd == "approve",
            "note": sys.argv[3] if len(sys.argv) > 3 else f"{cmd}d by operator",
        })
    else:
        sys.exit(f"unknown command: {cmd} (use list / approve <id> / reject <id>)")

    print(json.dumps(json.loads(out) if isinstance(out, str) else out, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
