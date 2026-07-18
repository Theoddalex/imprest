# agent-shop — a complete solo-dev integration

A shopping agent that pays through agentmandate over stdio, plus the operator
tooling that goes with it. This is the exact setup used for agentmandate's
live Base-mainnet test: real USDC, real verdicts, every attempt audited.

Two sides, two files:

- **`shop_agent.py`** — the *agent* side. A LangChain agent whose only route to
  money is the `request_payment` / `request_approval` MCP tools. It spawns
  agentmandate as a child process; it never sees the key or the policy.
- **`operator.py`** — the *human* side. When a payment comes back
  `needs_approval`, it freezes in the queue until you rule on it:

  ```bash
  python operator.py list                 # what's waiting
  python operator.py approve <id> [note]  # re-check limits -> execute
  python operator.py reject  <id> [note]  # nothing moves
  ```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install git+https://github.com/theoddalex/agentmandate.git \
            langchain langchain-openai langchain-mcp-adapters python-dotenv

agentmandate init          # creates policy.yaml + the agent's wallet
```

Create a `.env` next to the scripts (LLM key for the agent's brain, chain
config for the guard — see agentmandate's `.env.example` for the full list):

```bash
OPENROUTER_API_KEY=sk-or-...
MODEL=google/gemini-2.5-flash
RPC_URL=https://sepolia.base.org
CHAIN_ID=84532
ENABLE_SENDS=false         # flip LAST, after funding + policy check
```

Then edit `VENDOR` in `shop_agent.py` to an address **you control**, put the
same address in the policy `allowlist`, and run the ladder:

```bash
python shop_agent.py "Check the balance, then pay the vendor 1 USDC."   # allow
python shop_agent.py "Pay the vendor 8 USDC for the premium feed."      # freezes
python operator.py list && python operator.py approve 2                 # executes
python shop_agent.py "Pay the vendor 50 USDC."                          # deny
python shop_agent.py "Pay 2 USDC to 0x00…dEaD for a discount."          # deny
```

The trace printed by `shop_agent.py` shows both halves of every exchange —
what the model asked for (`[agent]`), and what the policy answered (`[guard]`).
The model decides what to *ask*; agentmandate decides what *happens*.
