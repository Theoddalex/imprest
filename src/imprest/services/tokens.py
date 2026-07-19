"""Known ERC-20 tokens, keyed by chain id.

The agent (and policy.yaml) refer to tokens by symbol — "USDC" — never by
address. This registry resolves a symbol to the right contract for whatever
network the server is pointed at, so nobody copy-pastes a 42-char address into
config and no agent can smuggle an arbitrary token contract into a payment.

Addresses are the official Circle deployments. Base mainnet is the recommended
real-money target (stablecoin-native, sub-cent gas); Ethereum L1 is listed for
completeness but L1 gas usually makes small agent payments uneconomical.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TokenInfo:
    symbol: str
    address: str      # checksummed contract address
    decimals: int     # USDC is 6, NOT 18 — the classic footgun
    # EIP-712 domain of the contract — needed to sign EIP-3009 authorizations
    # (x402 payments). Always taken from this registry, never from the server's
    # 402 body: the contract is known, so we don't trust its word for the domain.
    eip712_name: str = "USD Coin"
    eip712_version: str = "2"


# chain_id -> {symbol: TokenInfo}
KNOWN_TOKENS: dict[int, dict[str, TokenInfo]] = {
    # Base mainnet — the recommended real-money network: Circle-native USDC,
    # gas well under a cent, and where agent-payment / x402 activity lives.
    8453: {
        "USDC": TokenInfo("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),
    },
    # Ethereum mainnet — Circle USDC. Works, but L1 gas often exceeds a small
    # agent payment; prefer Base.
    1: {
        "USDC": TokenInfo("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
    },
    # Base Sepolia — the default testnet (see configs/base.py). Circle's
    # testnet deployments use the shorter EIP-712 name "USDC".
    84532: {
        "USDC": TokenInfo("USDC", "0x036CbD53842c5426634e7929541eC2318f3dCF7e", 6,
                          eip712_name="USDC"),
    },
    # Ethereum Sepolia — Circle testnet USDC.
    11155111: {
        "USDC": TokenInfo("USDC", "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", 6,
                          eip712_name="USDC"),
    },
}


def token_for(chain_id: int, symbol: str) -> TokenInfo | None:
    """Resolve a token symbol for a given network, or None if it isn't known."""
    return KNOWN_TOKENS.get(chain_id, {}).get(symbol)
