"""Runtime settings, loaded from environment / .env.

Mirrors the work backend's configs/base.py -> `settings` singleton pattern,
using pydantic-settings so config is typed and validated at startup.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Ethereum (Sepolia testnet by default — NEVER default to mainnet) ---
    rpc_url: str = "https://ethereum-sepolia-rpc.publicnode.com"
    chain_id: int = 11155111  # Sepolia
    # Path to the agent's throwaway keystore. Testnet only.
    keystore_path: str = "wallet.key"

    # --- Policy ---
    policy_path: str = "policy.yaml"

    # --- Audit ---
    audit_db_path: str = "audit.db"

    # --- Safety switch: writes are OFF unless explicitly enabled ---
    # Even on testnet, the agent can't send until you opt in.
    enable_sends: bool = False


settings = Settings()
