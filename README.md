# agentpay

**Programmable spend limits and audit trails so AI agents can pay for things
without risking the wallet.**

AI agents are probabilistic — they can be prompt-injected, loop, or simply
choose the wrong tool. The moment an agent can move money, one bad decision is
irreversible. `agentpay` is the guardrail layer between an agent and an Ethereum
wallet: every payment the agent requests is checked against a policy it **cannot
override**, and every attempt is logged.

Think *corporate-card controls (Ramp/Brex) or Stripe Radar — but for agents.*

## How it works

```
Agent: "pay 50 USDC to 0xabc… for the data API"
        │  (MCP tool call: request_payment, asset="USDC")
        ▼
   ┌───────────────────────────── agentpay ─────────────────────────────┐
   │  policy engine:  per-tx cap · hourly/daily budget · allow/deny      │
   │                  list · rate limit · human-approval threshold        │
   └─────────────────────────────────────────────────────────────────────┘
        │ ALLOW → sign & send (testnet)      │ DENY → block + log
        │ NEEDS_APPROVAL → queue for human   ▼
        ▼           │                  agent gets a clear reason
   tx executes,     └─► operator approves → re-check limits → execute
   logged                                   every attempt is audited
```

Payments can move **ETH or ERC-20 tokens (USDC)**, and agents can `request_payment`
or `request_approval` (a guarded token allowance — capped to an exact amount,
never unlimited). Granted allowances are tracked in an **allowance ledger**: they
outlive budget windows, so the *total* an agent has live at once is capped too
(`max_outstanding_allowance`), and `approve(spender, 0)` revokes to free the cap.
A `needs_approval` verdict is no longer a dead end: it queues
for a human operator, who approves or rejects it (`resolve_approval`) — and hard
limits are re-checked at approval time, so a human "yes" can't bust a budget.

The **MCP server is the product**; the LangChain agent in `examples/` is just
one client. Any MCP-aware client (Claude Desktop, Cursor, another agent) can use
the same server.

## Design principles

- **Non-custodial, testnet-first.** Defaults to Base Sepolia. Sends are OFF
  until you explicitly enable them. Never put a mainnet key behind an autonomous
  agent.
- **ETH and stablecoins.** Native ETH plus ERC-20 tokens (USDC). Each asset has
  its own policy limits and its own budget — 50 USDC never eats into an ETH
  ceiling — and a token is payable only if the policy names it.
- **The policy engine is pure logic** (`src/agentpay/services/policy.py`) — no
  I/O — so it is exhaustively unit-tested. The code guarding money is the code
  under the most tests (103 across the engine, auth, audit, ERC-20, approvals,
  the allowance ledger, and the payment flow).
- **Config, not code.** Limits live in `policy.yaml`.

## Layout

```
main.py                          # repo-root shim (python main.py)
src/agentpay/
├── main.py                      # console entrypoint (`agentpay`)
├── application.py               # app factory: create_application()
├── api/payments.py              # MCP tools (transport)
├── services/
│   ├── policy.py                # ⭐ the policy engine — pure, tested
│   ├── audit.py                 # append-only SQLite audit log
│   ├── auth.py                  # Bearer API-key auth + per-request identity
│   ├── chain.py                 # web3.py wrapper — ETH + ERC-20 (Base Sepolia)
│   ├── tokens.py                # known-token registry (symbol → address/decimals)
│   └── wallet.py                # throwaway testnet key
├── schemas/schemas.py           # contracts (Decimal money, dataclasses)
└── configs/base.py              # pydantic settings
tests/                           # 103 tests — policy, auth, audit, ERC-20, approvals, allowances
examples/demo_agent.py           # a LangChain agent that uses the server
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[demo,dev]"
cp .env.example .env

pytest                 # prove the policy engine
agentpay               # run the MCP server (stdio)
python examples/demo_agent.py   # watch an agent get allowed / blocked / gated
```

## Deploying it

The wallet owner runs the server; agents connect as clients and set nothing.

**Local (stdio)** — each MCP client spawns its own server process:

```json
{"agentpay": {"transport": "stdio", "command": "agentpay"}}
```

**Hosted (HTTP)** — one server for the whole org; developers get a URL and an
API key. The server **refuses to start without keys** (an open endpoint would
mean anyone who can reach it can spend the budget):

```bash
TRANSPORT=streamable-http \
AGENTPAY_API_KEYS='sk-supp-…:support-bot,sk-proc-…:procurement' agentpay
# or
docker build -t agentpay . && docker run -p 8000:8000 \
  -e AGENTPAY_API_KEYS='…' -v $(pwd)/policy.yaml:/app/policy.yaml agentpay
```

```json
{"agentpay": {"transport": "streamable_http",
              "url": "http://payments.internal:8000/mcp",
              "headers": {"Authorization": "Bearer sk-supp-…"}}}
```

The API key is the agent's identity: it selects that agent's policy section in
`policy.yaml` and attributes its audit trail. The same request can be denied
for `support-bot` (0.01/tx cap) and allowed for `procurement` (0.05/tx) —
identity decides. Unauthenticated requests get a 401 before any tool runs.

To use the approval-completion flow in hosted mode, also set
`AGENTPAY_ADMIN_KEYS='sk-admin-…:ops'` — a human operator with an admin key can
`list_pending_approvals` and `resolve_approval`; agents (regular keys) cannot,
so no agent can sign off its own `needs_approval` payment. Over stdio the local
operator is the admin automatically.

Either way, the client's agent code never sees the policy, the keys, or the
audit log — it only gets `request_payment` and a verdict.

> **Hosted-mode operational notes.** Bearer keys travel in headers — terminate
> TLS at your ingress/reverse proxy; never expose the plain HTTP port publicly.
> The server is **single-process** today: the per-agent budget lock guarantees
> no double-spend within one process, but running multiple workers/replicas
> against one `audit.db` is not yet safe (needs DB-level locking). Run one
> replica per wallet until then.

## Status

Working v1: pure policy engine, per-agent + per-asset policies, guarded token
`approve()` with an **allowance ledger** (total live allowances capped as a
standing liability, revoke supported), a human approval-completion flow
(admin-gated, budget + ledger re-checked at approval time), Bearer-key auth,
append-only audit log, structured logging, real Base Sepolia sends of **ETH and
USDC**, stdio + hosted HTTP transports, and a LangChain demo agent. 103 tests.

## Security checks

Every push runs the app-sec pipeline (`.github/workflows/ci.yml`), mirrored
locally by `make security`:

- **bandit** — SAST over `src/` (the code handling keys, auth, and SQL)
- **Trivy** — dependency CVEs (SCA), committed-secret scan (a `wallet.key` or
  API key in a commit fails the build), Dockerfile misconfig, and the built
  image (base OS + installed packages)

All findings gate at HIGH/CRITICAL. agentpay deploys no custom smart
contracts, so the risk surface is the application itself — these checks cover
it; an external review is still the gate before real funds.

## Known limitations (testnet-first — read before mainnet)

These are deliberate boundaries of the current design, verified by a `/ship`
review. None risks testnet funds; all are gated before real money.

- **The allowance ledger is conservative and off-chain.** It assumes the full
  last-approved amount to each spender is still live (a spender may have already
  pulled some — the real liability can only be *lower* than what we cap), and it
  reconstructs the ledger from agentpay's own audit log: allowances granted
  outside agentpay (or before it) are invisible to it. Start from a wallet with
  no pre-existing approvals, or revoke them first. On-chain `allowance()`
  reconciliation is on the roadmap.
- **Rate limiting counts only allowed spends.** Denied and `needs_approval`
  attempts don't count toward `rate_limit_per_minute`, and the pending-approval
  queue is unbounded/unpaginated — a looping agent can flood the audit log.
- **Single wallet, single process.** All agents sign from one keystore; the
  per-agent lock prevents double-spend within one process, but concurrent
  in-flight txs can race on the nonce, and multiple workers/replicas against one
  `audit.db` are not safe. Run one replica per wallet.
- **stdio makes the caller its own approver.** The "an agent can't approve its
  own payment" guarantee holds over HTTP (separate admin keys); over stdio the
  local operator is both. Hard limits are still re-checked at approval time.
- **Address validation is hex-shape only** (no EIP-55 checksum) — a mistyped but
  well-formed address will send. Use the allowlist for known recipients.

> **Hosted-mode operational notes.** Bearer keys travel in headers — terminate
> TLS at your ingress/reverse proxy; never expose the plain HTTP port publicly.
> Keep `AGENTPAY_API_KEYS` and `AGENTPAY_ADMIN_KEYS` disjoint (the server refuses
> to start otherwise). See the single-process limitation above.

## Roadmap

- **On-chain allowance reconciliation.** Cross-check the ledger against live
  `allowance()` reads so spent-down grants free the cap, and pre-existing
  out-of-band approvals are detected instead of invisible.
- **Postgres audit backend.** Replaces the SQLite file — unlocks multi-replica
  deployment *and* cross-process budget atomicity (`SELECT … FOR UPDATE`),
  lifting the single-process limitation above. One swap, both wins.
- **Abuse limits.** Count all attempts toward the rate limit; bound, paginate,
  and expire the pending-approval queue; retain/rotate the audit log.
