import json
import os
from typing import List

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from prophet_sdk import MarketOutcome, ProphetClient


def _load_keypair(path: str) -> Keypair:
    with open(path, "r") as f:
        return Keypair.from_bytes(bytes(json.loads(f.read().strip())))


def _load_notary_keypairs() -> List[Keypair]:
    raw = os.getenv("NOTARY_KEYPAIR_PATHS", "").strip()
    if not raw:
        raise ValueError("NOTARY_KEYPAIR_PATHS missing")
    return [_load_keypair(path.strip()) for path in raw.split(",") if path.strip()]


def _load_outcome() -> MarketOutcome:
    raw = os.getenv("OUTCOME", "YES").strip().upper()
    mapping = {
        "YES": MarketOutcome.Yes,
        "NO": MarketOutcome.No,
        "INVALID": MarketOutcome.Invalid,
    }
    if raw not in mapping:
        raise ValueError("OUTCOME must be one of YES, NO, INVALID")
    return mapping[raw]


def main():
    client = ProphetClient()

    market_env = os.getenv("MARKET_PUBKEY", "").strip()
    if not market_env:
        print("MARKET_PUBKEY missing")
        return

    market = Pubkey.from_string(market_env)
    market_acc = client.fetch_market(market)
    if market_acc is None:
        print(f"Market not found: {market}")
        return

    if market_acc.notary_config == Pubkey.default():
        print("Market does not have a notary_config; use resolve_signed_relayer.py for legacy compatibility flow.")
        return

    try:
        notary_keypairs = _load_notary_keypairs()
        outcome = _load_outcome()
    except Exception as e:
        print(f"Failed to load inputs: {e}")
        return

    proof_hash_hex = os.getenv("PROOF_HASH_HEX", "").strip()
    public_inputs_hash_hex = os.getenv("PUBLIC_INPUTS_HASH_HEX", "").strip()

    proof_hash = bytes.fromhex(proof_hash_hex) if proof_hash_hex else bytes([0] * 32)
    public_inputs_hash = (
        bytes.fromhex(public_inputs_hash_hex) if public_inputs_hash_hex else bytes([0] * 32)
    )

    if len(proof_hash) != 32 or len(public_inputs_hash) != 32:
        print("PROOF_HASH_HEX and PUBLIC_INPUTS_HASH_HEX must decode to 32 bytes")
        return

    print(f"Resolving v2 threshold market {market}...")
    print(f"  Notary Config: {market_acc.notary_config}")
    print(f"  Outcome: {outcome.name}")
    print(f"  Notary Signers Provided: {len(notary_keypairs)}")

    try:
        sig = client.resolve_market_threshold(
            market=market,
            notary_config=market_acc.notary_config,
            resolver_hash=market_acc.resolver_hash,
            open_ts=market_acc.open_ts,
            resolve_ts=market_acc.resolve_ts,
            outcome=outcome,
            proof_hash=proof_hash,
            public_inputs_hash=public_inputs_hash,
            notary_keypairs=notary_keypairs,
            relayer_keypair=client.payer,
        )
        print(f"Market resolved permissionlessly via threshold flow: {sig}")
    except Exception as e:
        print(f"Failed: {e}")


if __name__ == "__main__":
    main()
