"""Tests for authentication parsing and per-agent policy selection."""

from __future__ import annotations

from decimal import Decimal

import pytest

from agentpay.services.auth import parse_api_keys
from agentpay.services.policy import PolicyStore


# ---- API key parsing -----------------------------------------------------------

def test_parse_api_keys_happy_path():
    keys = parse_api_keys("sk-aaa:support-bot, sk-bbb:procurement")
    assert keys == {"sk-aaa": "support-bot", "sk-bbb": "procurement"}


def test_parse_api_keys_empty_string_means_no_keys():
    assert parse_api_keys("") == {}


@pytest.mark.parametrize("raw", ["justakey", "key:", ":agent"])
def test_parse_api_keys_rejects_malformed_entries(raw):
    with pytest.raises(ValueError):
        parse_api_keys(raw)


# ---- PolicyStore ----------------------------------------------------------------

DEFAULT = dict(
    per_transaction_max="0.05",
    daily_max="0.20",
    hourly_max="0.10",
    rate_limit_per_minute=5,
    approval_threshold="0.02",
)


def test_agent_override_merges_over_default():
    store = PolicyStore(DEFAULT, {"support-bot": {"per_transaction_max": "0.01"}})
    p = store.for_agent("support-bot")
    assert p.per_transaction_max == Decimal("0.01")   # overridden
    assert p.daily_max == Decimal("0.20")             # inherited from default


def test_unknown_agent_gets_the_default_policy():
    store = PolicyStore(DEFAULT, {"support-bot": {"per_transaction_max": "0.01"}})
    p = store.for_agent("some-new-agent")
    assert p.per_transaction_max == Decimal("0.05")


def test_flat_legacy_yaml_is_default_for_everyone(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text(
        "per_transaction_max: 0.05\ndaily_max: 0.2\nhourly_max: 0.1\n"
        "rate_limit_per_minute: 5\napproval_threshold: 0.02\n"
    )
    store = PolicyStore.load(str(f))
    assert store.for_agent("anyone").per_transaction_max == Decimal("0.05")


def test_identity_format_with_agents_section(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text(
        """
default:
  per_transaction_max: 0.05
  daily_max: 0.2
  hourly_max: 0.1
  rate_limit_per_minute: 5
  approval_threshold: 0.02
agents:
  procurement:
    per_transaction_max: 1.0
    daily_max: 2.0
"""
    )
    store = PolicyStore.load(str(f))
    assert store.for_agent("procurement").per_transaction_max == Decimal("1.0")
    assert store.for_agent("procurement").hourly_max == Decimal("0.1")  # inherited
    assert store.for_agent("intern-bot").per_transaction_max == Decimal("0.05")
