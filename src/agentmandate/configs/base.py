"""Runtime settings, loaded from environment / .env.

Mirrors the work backend's configs/base.py -> `settings` singleton pattern,
using pydantic-settings so config is typed and validated at startup.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Ethereum (Base Sepolia testnet by default — NEVER default to mainnet) ---
    # Base Sepolia is where most agent-payment / x402 / stablecoin activity lives,
    # and Circle's testnet USDC has a faucet there. Native-ETH gas works too.
    rpc_url: str = "https://sepolia.base.org"
    chain_id: int = 84532  # Base Sepolia
    # Path to the agent's throwaway keystore. Testnet only.
    keystore_path: str = "wallet.key"

    # --- Policy ---
    policy_path: str = "policy.yaml"

    # --- Audit ---
    audit_db_path: str = "audit.db"

    # --- Safety switch: writes are OFF unless explicitly enabled ---
    # Even on testnet, the agent can't send until you opt in.
    enable_sends: bool = False

    # --- Gas safety rails (the RPC is untrusted) ---
    # Hard ceiling on maxFeePerGas, in gwei. The RPC quotes the price but we
    # never sign above this — refuse instead. 50 gwei clears normal traffic on
    # Base (typ. <0.1 gwei) and Ethereum L1 (typ. 1-30 gwei) while blocking a
    # lying RPC. Worst-case gas cost is bounded by gas_limit x this ceiling.
    max_fee_gwei: float = 50.0
    # Fixed gas limit for ERC-20 transfer/approve (USDC needs ~65k). Never
    # estimated via the RPC, so the endpoint can't inflate it.
    erc20_gas_limit: int = 120_000
    # How long to wait for a tx to be mined before reporting it unconfirmed.
    receipt_timeout: int = 120

    # --- Transport ---
    # "stdio" for local spawn-per-client use; "streamable-http" to host the
    # server at a URL that many clients/agents connect to (the org setup).
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000

    # --- Identity / auth ---
    # HTTP: "key1:agent-a,key2:agent-b" — every request must present one of
    # these as a Bearer token. Empty + HTTP transport = server refuses to start
    # (set allow_anonymous=true to override, e.g. for local experiments).
    agentmandate_api_keys: str = ""
    # HTTP: admin keys, same "key:admin-id,..." format. Admins (human operators,
    # never agents) may resolve needs_approval payments; agents cannot approve
    # their own. Optional — omit if you don't use the approval-completion flow.
    agentmandate_admin_keys: str = ""
    allow_anonymous: bool = False
    # stdio: the identity of the local caller (the OS is the auth boundary).
    agent_id: str = "local"


settings = Settings()
