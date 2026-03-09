import os
import sys
import time
import argparse
import json
import hashlib
from solders.pubkey import Pubkey

# Ensure we can import the SDK from root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../sdk/python")))
from prophet_sdk import ProphetClient, derive_market_pda

def compute_resolver_hash(definition: dict) -> bytes:
    canonical_json = json.dumps(definition, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).digest()

def load_resolver_definition(path: str) -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Resolver file missing: {path}")
    with open(path, "r") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Resolver definition must be a JSON object")
    return data

def main():
    parser = argparse.ArgumentParser(description="Create a new Prophet Market")
    parser.add_argument("--resolver-file", required=True, help="Path to resolver definition JSON file")
    parser.add_argument("--mint", required=True, help="Quote Token Mint (Base58)")
    parser.add_argument("--notary-config", required=True, help="NotaryConfig pubkey (Base58)")
    parser.add_argument("--duration", type=int, default=3600, help="Duration in seconds until resolution")
    args = parser.parse_args()

    # Load Env
    rpc_url = os.getenv("RPC_URL", "https://api.devnet.solana.com")
    payer_path = os.getenv("PAYER_KEYPAIR_PATH")
    
    if not payer_path:
        print("Error: PAYER_KEYPAIR_PATH env var not set")
        sys.exit(1)

    client = ProphetClient(rpc_url=rpc_url, payer_keypair_path=payer_path)
    
    try:
        resolver_def = load_resolver_definition(args.resolver_file)
        resolver_hash = compute_resolver_hash(resolver_def)
    except Exception as e:
        print(f"Error loading resolver definition: {e}")
        sys.exit(1)

    quote_mint = Pubkey.from_string(args.mint)
    oracle_auth = client.payer.pubkey()
    notary_config = Pubkey.from_string(args.notary_config)

    now = int(time.time())
    open_ts = now
    lock_ts = now + args.duration
    resolve_ts = now + args.duration
    
    print("Creating Market...")
    print(f"  Mint:   {quote_mint}")
    print(f"  Resolver File: {args.resolver_file}")
    print(f"  Resolver Hash: {resolver_hash.hex()}")
    print(f"  Lock:   {lock_ts}")
    print(f"  Mode:   v2 threshold")
    print(f"  Notary: {notary_config}")

    try:
        sig = client.initialize_market_v2(
            resolver_hash=resolver_hash,
            open_ts=open_ts,
            lock_ts=lock_ts,
            resolve_ts=resolve_ts,
            notary_config=notary_config,
            oracle_authority=oracle_auth,
            quote_mint=quote_mint,
        )
        print(f"\nSuccess! Tx: {sig}")
        
        market_pda, _ = derive_market_pda(resolver_hash, open_ts, client.program_id)
        print(f"Market Address: {market_pda}")
        print(f"Resolver Hash (Hex): {resolver_hash.hex()}")
        
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    main()
