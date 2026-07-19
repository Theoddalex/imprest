"""x402 — pay-per-request HTTP payments (the revived "402 Payment Required").

The flow this module implements (x402 v1, scheme "exact", EVM):

    1. GET the resource. A paid endpoint answers 402 with a JSON body listing
       payment requirements: price, payee, token contract, network.
    2. We parse that body and match it against OUR network and OUR token
       registry — a server cannot make us sign for an unknown contract.
    3. The policy engine judges the price like any other payment (that part
       lives in api/payments.py, not here).
    4. On ALLOW we sign an EIP-3009 `transferWithAuthorization` — a typed-data
       signature authorising the payee's facilitator to pull EXACTLY that
       amount, once, within a short validity window. No gas is spent by us;
       nothing is broadcast from our wallet.
    5. Retry the request with the signature in the `X-PAYMENT` header; the
       server verifies, settles on-chain, and returns the resource plus an
       `X-PAYMENT-RESPONSE` header carrying the settlement tx hash.

Security posture: the signature is as good as money (it IS the payment), so it
is only ever produced after the policy engine returns ALLOW, and its window is
bounded — validBefore caps how long the server can sit on it.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import socket
from dataclasses import dataclass
from decimal import Decimal
from urllib.parse import urlparse

from imprest.services.tokens import KNOWN_TOKENS

# x402 network identifiers per chain — both the human name used by x402 v1
# and the CAIP-2 form some newer servers emit.
NETWORK_NAMES: dict[int, tuple[str, ...]] = {
    8453: ("base", "eip155:8453"),
    84532: ("base-sepolia", "eip155:84532"),
    1: ("ethereum", "eip155:1"),
    11155111: ("sepolia", "eip155:11155111"),
}

# Never sign an authorization the server can hold for longer than this,
# whatever maxTimeoutSeconds it asks for.
_MAX_VALIDITY_SECONDS = 900

# A payment demand is tiny JSON; anything larger is either a mistake or an
# attempt to exhaust memory on the host that holds the wallet key.
_MAX_BODY_BYTES = 256 * 1024

# How many redirect hops we follow, re-validating each. Real x402 endpoints
# rarely redirect; one hop covers the legitimate case and bounds how long a
# hostile server can string us along under the agent lock.
_MAX_REDIRECTS = 1


class X402Error(Exception):
    """A 402 response we cannot (or must not) satisfy."""


class X402Unsafe(X402Error):
    """A URL/host we refuse to fetch (SSRF guard)."""


@dataclass(frozen=True)
class X402Offer:
    """One payment requirement from a 402 body, validated against our config."""

    network: str            # the identifier the server used (echoed back)
    amount: Decimal         # price in whole token units (e.g. 0.001 USDC)
    amount_base_units: int  # the same, in base units (what gets signed)
    pay_to: str             # the payee address (the policy's `recipient`)
    asset_address: str      # token contract — verified against the registry
    asset_symbol: str       # registry symbol, e.g. "USDC"
    decimals: int
    domain_name: str        # EIP-712 domain of the token contract
    domain_version: str
    max_timeout: int        # server's requested validity window (seconds)


def parse_402(body: dict, chain_id: int) -> X402Offer:
    """Pick the payment requirement we can satisfy, or raise X402Error.

    "Can satisfy" means: x402 v1, scheme "exact", the server's network is OUR
    configured chain, and the asset is a contract from OUR token registry. The
    registry check is the crucial one — the amount is denominated in whatever
    contract the server names, so an unknown contract would make the price
    meaningless (18-decimals dust or a worthless token spoofing USDC).
    """
    if body.get("x402Version") not in (None, 1):
        raise X402Error(f"unsupported x402 version {body.get('x402Version')!r}")
    accepts = body.get("accepts") or []
    if not accepts:
        raise X402Error("402 response lists no payment requirements")

    our_networks = NETWORK_NAMES.get(chain_id, ())
    tokens_by_address = {
        t.address.lower(): t for t in KNOWN_TOKENS.get(chain_id, {}).values()
    }

    reasons = []
    for req in accepts:
        if req.get("scheme") != "exact":
            reasons.append(f"scheme {req.get('scheme')!r} not supported")
            continue
        network = req.get("network", "")
        if network not in our_networks:
            reasons.append(f"network {network!r} is not this server's chain")
            continue
        asset = str(req.get("asset", ""))
        token = tokens_by_address.get(asset.lower())
        if token is None:
            reasons.append(f"asset {asset} is not in the token registry")
            continue

        try:
            base_units = int(req["maxAmountRequired"])
            pay_to = str(req["payTo"])
        except (KeyError, ValueError, TypeError) as e:
            raise X402Error(f"malformed payment requirement: {e}") from e
        if base_units < 0:
            raise X402Error("negative maxAmountRequired")
        # A recorded ALLOW must always be executable: reject a malformed payee
        # here rather than let it become a poisoned ALLOW that only fails at
        # signing time (mirrors the recipient check on the direct path).
        if not _looks_like_address(pay_to):
            raise X402Error(f"payTo {pay_to!r} is not a valid address")

        return X402Offer(
            network=network,
            amount=Decimal(base_units) / (Decimal(10) ** token.decimals),
            amount_base_units=base_units,
            pay_to=pay_to,
            asset_address=token.address,
            asset_symbol=token.symbol,
            decimals=token.decimals,
            # The token's EIP-712 domain comes from OUR registry — the contract
            # is already known, so we never take the server's word for it (a
            # wrong value only yields an unusable signature, but trusting the
            # registry is strictly safer and keeps the signed domain constant).
            domain_name=token.eip712_name,
            domain_version=token.eip712_version,
            max_timeout=int(req.get("maxTimeoutSeconds") or 300),
        )

    raise X402Error("no satisfiable payment option: " + "; ".join(reasons))


def payment_nonce(seed: str) -> str:
    """A deterministic bytes32 nonce derived from a payment's identity.

    EIP-3009's nonce is the on-chain replay/idempotency key. Deriving it from
    the payment's stable identity (agent + audit row + terms) means a RETRY of
    the same logical payment re-emits the SAME authorization — so if the first
    attempt already settled on-chain, the facilitator rejects the duplicate
    nonce instead of pulling funds a second time. A random nonce here would
    silently double-pay on retry.
    """
    return "0x" + hashlib.sha256(seed.encode()).hexdigest()


def sign_payment_header(account, offer: X402Offer, chain_id: int,
                        now_unix: int, nonce: str) -> str:
    """Sign an EIP-3009 transferWithAuthorization and encode the X-PAYMENT header.

    The signature authorises moving EXACTLY `offer.amount_base_units` to
    `offer.pay_to`, once (the caller passes a deterministic `nonce` so retries
    are idempotent — see payment_nonce), and only within [now-60s, now+window]
    — the window is the server's requested timeout capped at
    _MAX_VALIDITY_SECONDS. Precondition: policy already returned ALLOW.
    """
    from eth_account.messages import encode_typed_data

    valid_after = now_unix - 60  # tolerate small clock skew
    valid_before = now_unix + max(60, min(offer.max_timeout, _MAX_VALIDITY_SECONDS))

    signable = encode_typed_data(
        domain_data={
            "name": offer.domain_name,
            "version": offer.domain_version,
            "chainId": chain_id,
            "verifyingContract": offer.asset_address,
        },
        message_types={
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ]
        },
        message_data={
            "from": account.address,
            "to": offer.pay_to,
            "value": offer.amount_base_units,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": nonce,
        },
    )
    signature = account.sign_message(signable).signature.to_0x_hex()

    payment = {
        "x402Version": 1,
        "scheme": "exact",
        "network": offer.network,
        "payload": {
            "signature": signature,
            "authorization": {
                "from": account.address,
                "to": offer.pay_to,
                "value": str(offer.amount_base_units),
                "validAfter": str(valid_after),
                "validBefore": str(valid_before),
                "nonce": nonce,
            },
        },
    }
    return base64.b64encode(json.dumps(payment).encode()).decode()


def decode_settlement(header_value: str | None) -> dict:
    """Decode the X-PAYMENT-RESPONSE header (settlement receipt), if present."""
    if not header_value:
        return {}
    try:
        return json.loads(base64.b64decode(header_value))
    except Exception:  # noqa: BLE001 - a bad receipt must not mask a paid 200
        return {"raw": header_value}


def _looks_like_address(addr) -> bool:
    """Cheap 0x + 40-hex address check (kept local so x402 has no api import)."""
    if not isinstance(addr, str) or not addr.startswith("0x") or len(addr) != 42:
        return False
    try:
        int(addr, 16)
        return True
    except ValueError:
        return False


def _ip_is_public(ip_str: str) -> bool:
    """True only for globally-routable unicast addresses.

    Uses the stdlib's authoritative `is_global` rather than a hand-rolled
    blocklist — that also covers CGNAT shared space (100.64.0.0/10) and the
    benchmarking/test ranges a blocklist of is_private/is_loopback/etc. misses.
    IPv4-mapped IPv6 (::ffff:169.254.169.254) is unwrapped first, closing that
    classic metadata-SSRF bypass.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


def _ip_is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def check_url(url: str, *, allow_local: bool = False, resolve=None) -> str | None:
    """Reject URLs we must never fetch (SSRF guard). Returns an error or None.

    Requires https (http only when `allow_local`, for localhost testing), and
    resolves the host — refusing if ANY resolved address is non-public. This
    runs on the ORIGINAL url and must be re-run on every redirect hop, because
    a redirect can point a vetted host at an internal one (see safe_get).

    `resolve` is a getaddrinfo-compatible callable (a test seam; defaults to
    socket.getaddrinfo). Residual risk: a DNS name could resolve to a public IP
    here and a private one at connect time (rebinding). Deployments guarding
    real funds should run this host with egress restricted to payee networks.
    """
    resolve = resolve or socket.getaddrinfo
    try:
        parts = urlparse(url)
    except ValueError:
        return f"unparseable URL {url!r}"
    host = parts.hostname
    if not host:
        return f"URL has no host: {url!r}"
    if parts.scheme == "http":
        if allow_local and host in ("localhost", "127.0.0.1", "::1"):
            return None
        return f"URL must be https, got {url!r}"
    if parts.scheme != "https":
        return f"unsupported URL scheme in {url!r}"
    # A bare IP literal is vetted directly (no DNS needed).
    if _ip_is_literal(host):
        if _ip_is_public(host.strip("[]")):
            return None
        return f"refusing to fetch non-public address {host}"
    # Resolve and vet every address the host maps to.
    try:
        infos = resolve(host, parts.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return f"cannot resolve host {host!r}: {e}"
    for info in infos:
        ip = info[4][0]
        if not _ip_is_public(ip):
            return f"refusing to fetch {host!r}: resolves to non-public address {ip}"
    return None


@dataclass(frozen=True)
class HttpResult:
    """A minimal, fully-buffered HTTP response (the stream is already closed).

    Only the fields the x402 flow needs, so callers never touch a live/closed
    httpx stream. `json()` raises like httpx on a non-JSON body.
    """

    status_code: int
    headers: dict
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.content)


def safe_get(client, url: str, headers: dict | None = None, *,
             allow_local: bool = False, resolve=None) -> HttpResult:
    """GET `url` with SSRF vetting on every hop and a response-size cap.

    The httpx client MUST be configured with follow_redirects=False; we follow
    redirects manually so check_url runs against each Location (httpx's own
    redirect following would skip the guard and could reach an internal host).
    `resolve` is a getaddrinfo test seam. Raises X402Unsafe / X402Error.

    Sensitive `headers` (the signed X-PAYMENT authorization) are sent ONLY to
    the original host; if that request redirects, we do NOT re-present the
    signature to the redirect target the server chose — the caller treats the
    redirect as a failure instead.
    """
    if getattr(client, "follow_redirects", False):
        # The manual hop loop IS the SSRF guard; an auto-following client would
        # silently bypass check_url on redirect targets. Fail loud, not open.
        raise X402Error("x402 http client must have follow_redirects=False")
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        err = check_url(current, allow_local=allow_local, resolve=resolve)
        if err:
            raise X402Unsafe(err)
        # Stream so we can abort a giant body before it is fully buffered.
        with client.stream("GET", current, headers=headers) as resp:
            if resp.is_redirect and resp.headers.get("location"):
                if headers:
                    # Never resend the signed authorization to a redirect hop.
                    raise X402Error(
                        "server redirected a paid (X-PAYMENT) request; "
                        "refusing to re-present the authorization elsewhere"
                    )
                current = str(resp.url.join(resp.headers["location"]))
                continue
            chunks, total = [], 0
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > _MAX_BODY_BYTES:
                    raise X402Error(
                        f"402 response body exceeds {_MAX_BODY_BYTES} bytes; refusing"
                    )
                chunks.append(chunk)
            # Lowercase header keys for case-insensitive lookups by callers.
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return HttpResult(resp.status_code, hdrs, b"".join(chunks))
    raise X402Error(f"too many redirects fetching {url!r}")
