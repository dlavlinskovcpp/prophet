import os
import sys
import time
import argparse
import json
from solders.pubkey import Pubkey
from solders.keypair import Keypair

# Ensure we can import the SDK from root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../sdk/python")))
from prophet_sdk import ProphetClient, derive_market_pda

def main():
    parser = argparse.ArgumentParser(description="Create a new Prophet Market")
    parser.add_argument("--oracle", required=True, help="Oracle Authority Pubkey (Base58)")
    parser.add_argument("--mint", required=True, help="Quote Token Mint (Base58)")
    parser.add_argument("--duration", type=int, default=3600, help="Duration in seconds until resolution")
    args = parser.parse_args()

    # Load Env
    rpc_url = os.getenv("RPC_URL", "https://api.devnet.solana.com")
    payer_path = os.getenv("PAYER_KEYPAIR_PATH")
    
    if not payer_path:
        print("Error: PAYER_KEYPAIR_PATH env var not set")
        sys.exit(1)

    client = ProphetClient(rpc_url=rpc_url, payer_keypair_path=payer_path)
    
    oracle_auth = Pubkey.from_string(args.oracle)
    quote_mint = Pubkey.from_string(args.mint)
    
    # Generate unique resolver hash (random for this script)
    resolver_hash = os.urandom(32)
    
    now = int(time.time())
    open_ts = now
    lock_ts = now + args.duration
    resolve_ts = now + args.duration
    
    print(f"Creating Market...")
    print(f"  Oracle: {oracle_auth}")
    print(f"  Mint:   {quote_mint}")
    print(f"  Lock:   {lock_ts}")

    try:
        sig = client.initialize_market(
            resolver_hash=resolver_hash,
            open_ts=open_ts,
            lock_ts=lock_ts,
            resolve_ts=resolve_ts,
            oracle_authority=oracle_auth,
            quote_mint=quote_mint
        )
        print(f"\nSuccess! Tx: {sig}")
        
        market_pda, _ = derive_market_pda(resolver_hash, open_ts, client.program_id)
        print(f"Market Address: {market_pda}")
        print(f"Resolver Hash (Hex): {resolver_hash.hex()}")
        
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    main()