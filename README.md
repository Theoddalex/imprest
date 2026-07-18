# agentmandate

[![ci](https://github.com/theoddalex/agentmandate/actions/workflows/ci.yml/badge.svg)](https://github.com/theoddalex/agentmandate/actions/workflows/ci.yml)

**Programmable spend limits and audit trails so AI agents can pay for things
without risking the wallet.**

AI agents are probabilistic — they can be prompt-injected, loop, or simply
choose the wrong tool. The moment an agent can move money, one bad decision is
irreversible. `agentmandate` is the guardrail layer between an agent and an
Ethereum wallet: every payment the agent requests is checked against a policy
it **cannot override**, and every attempt is logged.

Think *corporate-card controls (Ramp/Brex) or Stripe Radar — but for agents*.
The model in one line: **give your agent an allowance, not your keys.**

## Quick start

```bash
pip install git+https://github.com/theoddalex/agentmandate.git

agentmandate init     # the one setup ceremony:
                      #   ✓ policy.yaml — your agent's limits (edit them)
                      #   ✓ a dedicated wallet, generated locally from OS entropy
                      #   → prints the address to fund
agentmandate status   # balances, gas headroom, active limits, sends switch
```

Then point any MCP client (Claude Desktop, Cursor, a LangChain agent — see
`examples/`) at the server, and the agent gets `request_payment` and a verdict —
nothing else:

```json
{"agentmandate": {"transport": "stdio", "command": "agentmandate"}}
```

Defaults are safe by construction: **Base Sepolia testnet, sends OFF** until you
explicitly set `ENABLE_SENDS=true`. On testnets you may even skip `init` — a
throwaway wallet auto-creates on first use. On **mainnet** chains agentmandate
refuses to create a key silently: real-money wallets only come into existence
when a human runs `init`.

## The wallet model: a prepaid card

The agent never gets your wallet. `init` generates a **fresh, dedicated wallet**
for the agent; you fund it with only what the agent may spend, and top it up
like a prepaid card. That makes the maximum possible loss the card balance —
a physics-level cap that holds even if every software check failed. The policy
engine is the soft limit; the balance is the hard one. Your real wallet
(hardware, exchange, MetaMask) never touches agentmandate at all.

## How it works

```
agent: "pay 10 USDC to 0xabc… for the data API"
   │
   │  MCP tool call: request_payment(…, asset="USDC")
   ▼
┌────────────────────── agentmandate ──────────────────────┐
│ policy engine:  per-tx cap · hourly/daily budgets        │
│ allow/denylist · rate limit · approval threshold         │
└────────┬───────────────────┬────────────────────┬────────┘
         │                   │                    │
       ALLOW          NEEDS_APPROVAL            DENY
         ▼                   ▼                    ▼
 preflight, sign,     queue for operator:   block + log;
 broadcast, wait      approve → re-check    agent gets the
 for confirmation     limits → execute      exact reason
         │
         ▼
 tx mined + audited
```

Payments move **stablecoins (USDC) or ETH**. Stablecoins are the spending
lanes; in the default policy ETH is a **gas-only lane** with near-zero limits —
any real ETH transfer attempt looks anomalous and gets denied or escalated.

**The allowance ledger — the part nothing else has.** Agents can also
`request_approval` (a guarded ERC-20 `approve()`): always an exact amount,
never unlimited — the vector behind most token drains. Granted allowances
outlive every budget window, so agentmandate tracks them as **standing
liabilities**: the *total* live across all spenders is capped
(`max_outstanding_allowance`), and `approve(spender, 0)` revokes to free the
cap. Rolling budgets alone can't see this risk; the ledger closes it.

A `needs_approval` verdict is not a dead end: it queues for a human operator,
who approves or rejects (`resolve_approval`) — and hard limits are re-checked
at approval time, so a human "yes" can't bust a budget.

**x402 — pay-per-request APIs.** Agents can also buy paid HTTP resources with
`pay_x402(url, max_amount)`: agentmandate does the [x402](https://docs.cdp.coinbase.com/x402/welcome)
handshake (`402 Payment Required` → price quote), runs the quoted price through
the **same policy pipeline** — caps, budgets, allowlist, approval queue — and
only on ALLOW signs an EIP-3009 authorization for *exactly* the quoted amount
(gasless; the recipient's facilitator settles on-chain). The server's quote is
held to the agent's stated `max_amount`, the token contract must match the
registry, and if a frozen payment is approved later the terms are re-fetched —
a payee/asset change or a price hike refuses instead of paying.

The **MCP server is the product**; agents are just clients of it.

## Design principles

- **Non-custodial, blast-radius first.** Dedicated per-agent wallet, funded
  with pocket money. Keys are generated locally, never leave the machine, and
  never get created as a side effect on mainnet.
- **The RPC endpoint is untrusted.** Gas price is capped by a configurable
  ceiling (`MAX_FEE_GWEI`) and gas limits are fixed, never estimated — a
  lying RPC can neither overprice nor inflate a transaction. Worst-case gas
  cost is bounded at `gas_limit × ceiling`, always.
- **Broadcast is not success.** Every send waits for the receipt; reverts and
  timeouts fail the audit row. "Executed" means *mined with status 1*.
- **The policy engine is pure logic** (`src/agentmandate/services/policy.py`)
  — no I/O — so it is exhaustively unit-tested. The code guarding money is the
  code under the most tests (171 across the engine, auth, audit, ERC-20,
  approvals, the allowance ledger, x402, the chain rails, and the CLI).
- **Config, not code.** Limits live in `policy.yaml`. Each asset has its own
  limits and its own budget — 10 USDC never eats into an ETH ceiling — and a
  token is payable only if the policy names it.

## Deploying it

The wallet owner runs the server; agents connect as clients and set nothing.

**Local (stdio)** — each MCP client spawns its own server process; identity is
`AGENT_ID`, the OS is the auth boundary:

```json
{"agentmandate": {"transport": "stdio", "command": "agentmandate"}}
```

**Hosted (HTTP)** — one server for the whole org; developers get a URL and an
API key. The server **refuses to start without keys** (an open endpoint would
mean anyone who can reach it can spend the budget):

```bash
TRANSPORT=streamable-http \
AGENTMANDATE_API_KEYS='sk-supp-…:support-bot,sk-proc-…:procurement' agentmandate
# or
docker build -t agentmandate . && docker run -p 8000:8000 \
  -e AGENTMANDATE_API_KEYS='…' -v $(pwd)/policy.yaml:/app/policy.yaml agentmandate
```

```json
{"agentmandate": {"transport": "streamable_http",
              "url": "http://payments.internal:8000/mcp",
              "headers": {"Authorization": "Bearer sk-supp-…"}}}
```

The API key is the agent's identity: it selects that agent's policy section in
`policy.yaml` and attributes its audit trail. The same request can be denied
for `support-bot` and allowed for `procurement` — identity decides.
Unauthenticated requests get a 401 before any tool runs.

For the approval flow in hosted mode, also set
`AGENTMANDATE_ADMIN_KEYS='sk-admin-…:ops'` — a human with an admin key can
`list_pending_approvals` / `resolve_approval`; agents (regular keys) cannot, so
no agent signs off its own payment. Over stdio the local operator is the admin.

> **Hosted-mode operational notes.** Bearer keys travel in headers — terminate
> TLS at your ingress; never expose the plain HTTP port publicly. Keep API and
> admin keys disjoint (the server refuses to start otherwise). The server is
> **single-process** today: budget checks are atomic within one process, but
> multiple workers/replicas against one `audit.db` are not yet safe. Run one
> replica per wallet.

## Going to mainnet

**Base mainnet (chain 8453) is the recommended target** — Circle-native USDC
and sub-cent gas. The sequence:

```bash
CHAIN_ID=8453 RPC_URL=https://mainnet.base.org agentmandate init
```

1. `init` prints the funding address. Send it a small USDC float and a few
   dollars of ETH for gas — **withdraw on the Base network**, not Ethereum.
2. Edit `policy.yaml` down to numbers you'd let an autonomous process spend.
   Set the `allowlist` to known recipients. If your agent will legitimately
   discover *new* payees (vendors, APIs), set `unknown_recipient: ask` —
   an off-allowlist payment then freezes in the approval queue for you to
   rule on (one payment, one ruling; the address is not remembered) instead
   of being denied outright. Every other limit still applies first, so an
   over-cap request to a stranger dies on the cap, never reaching the queue.
3. Check the card: `agentmandate status`.
4. Flip `ENABLE_SENDS=true` **last**.

Treat the wallet as a hot-wallet float (see limitations below): it should never
hold more than you'd load onto a gift card.

## Layout

```
main.py                          # repo-root shim (python main.py)
src/agentmandate/
├── main.py                      # console entrypoint (`agentmandate`)
├── cli.py                       # operator CLI: init (the ceremony) + status
├── application.py               # app factory: create_application()
├── api/payments.py              # MCP tools (transport)
├── services/
│   ├── policy.py                # ⭐ the policy engine — pure, tested
│   ├── audit.py                 # append-only SQLite audit log
│   ├── auth.py                  # Bearer API-key auth + per-request identity
│   ├── chain.py                 # web3 wrapper — gas rails, nonce lock, receipts
│   ├── tokens.py                # known-token registry (symbol → address/decimals)
│   ├── x402.py                  # x402 pay-per-request: 402 parsing, EIP-3009 signing
│   └── wallet.py                # dedicated wallet: explicit create, mainnet guard
├── schemas/schemas.py           # contracts (Decimal money, dataclasses)
└── configs/base.py              # pydantic settings
tests/                           # 171 tests
examples/demo_agent.py           # a LangChain agent that uses the server
examples/agent-shop/             # complete solo-dev setup: agent + operator
                                 #   approve/reject CLI (the mainnet-test rig)
```

## Developing

```bash
git clone https://github.com/theoddalex/agentmandate && cd agentmandate
python -m venv .venv && source .venv/bin/activate
pip install -e ".[demo,dev]"
cp .env.example .env

pytest                           # 171 tests — the policy engine and the rails
python examples/demo_agent.py    # watch an agent get allowed / blocked / gated
```

## Status

**Tested live on Base mainnet** — an LLM agent running the full verdict ladder
with real USDC: payment allowed and mined, payment frozen for human approval
then executed, over-limit payment denied, an exact-amount allowance granted and
revoked (ledger and on-chain state verified in agreement), and a
non-allowlisted recipient blocked. Every attempt in the audit log with the rule
that fired; total gas for the ceremony ≈ $0.01. The setup used is
`examples/agent-shop/`.

Working v1, mainnet-hardened chain layer: pure policy engine, per-agent +
per-asset policies, guarded token `approve()` with the **allowance ledger**
(total live allowances capped, revoke supported), human approval flow
(admin-gated, re-checked at approval time), Bearer-key auth, append-only audit
log, gas-fee ceiling + fixed gas limits (untrusted RPC), pending-nonce with a
per-wallet lock, receipt-confirmed sends, balance preflight, `init`/`status`
operator CLI, USDC on Base + Ethereum (mainnet and testnets), **x402
pay-per-request purchases** (policy-guarded EIP-3009 signing), stdio + hosted
HTTP transports, and a LangChain demo agent. 171 tests.

## Security checks

Every push runs the app-sec pipeline (`.github/workflows/ci.yml`), mirrored
locally by `make security`:

- **bandit** — SAST over `src/` (the code handling keys, auth, and SQL)
- **Trivy** — dependency CVEs (SCA), committed-secret scan (a `wallet.key` or
  API key in a commit fails the build), Dockerfile misconfig, and the built
  image (base OS + installed packages)

All findings gate at HIGH/CRITICAL. agentmandate deploys no custom smart
contracts, so the risk surface is the application itself — these checks cover
it; an external review is still the gate before serious funds.

## Known limitations (read before mainnet)

These are deliberate boundaries of the current design.

- **The key file is unencrypted** (`wallet.key`, permissions 0600). This is the
  prepaid-card trade-off: the wallet is designed to hold a small float, not
  savings. Anyone with file access to the machine can take the float. An
  encrypted keystore is on the roadmap; the mitigation today is the funding
  model itself.
- **The allowance ledger is conservative and off-chain.** It assumes the full
  last-approved amount to each spender is still live (the real liability can
  only be *lower* than the cap), and it reconstructs state from agentmandate's
  own audit log: allowances granted outside agentmandate are invisible to it.
  Start from a wallet with no pre-existing approvals, or revoke them first.
- **Rate limiting counts only allowed spends.** Denied and `needs_approval`
  attempts don't count toward `rate_limit_per_minute`, and the pending-approval
  queue is unbounded — a looping agent can flood the audit log.
- **Single wallet, single process.** All agents sign from one keystore. The
  per-wallet nonce lock serialises concurrent sends within one process, but
  multiple workers/replicas against one `audit.db` are not safe. Run one
  replica per wallet.
- **stdio makes the caller its own approver.** The "an agent can't approve its
  own payment" guarantee holds over HTTP (separate admin keys); over stdio the
  local operator is both. Hard limits are still re-checked at approval time.
- **Address validation is hex-shape only** (no EIP-55 checksum) — a mistyped
  but well-formed address will send. Use the allowlist for known recipients.

## Roadmap

- **On-chain allowance reconciliation.** Cross-check the ledger against live
  `allowance()` reads so spent-down grants free the cap, and out-of-band
  approvals are detected instead of invisible.
- **Encrypted keystore.** Password-protected key at rest (eth_account native),
  unlocked via env at startup.
- **Postgres audit backend.** Replaces the SQLite file — unlocks multi-replica
  deployment *and* cross-process budget atomicity, lifting the single-process
  limitation. One swap, both wins.
- **Abuse limits.** Count all attempts toward the rate limit; bound, paginate,
  and expire the pending-approval queue; retain/rotate the audit log.
- **Non-custodial hosted control plane.** Split verdict from signing so a
  hosted agentmandate never holds customer keys: policy + audit + dashboard in
  the cloud, a client-side signer executing only server-issued, single-use
  vouchers — and, longer term, ERC-4337 session keys / spend permissions so the
  chain itself enforces the limits.
