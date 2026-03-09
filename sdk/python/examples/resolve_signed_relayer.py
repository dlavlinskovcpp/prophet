import os
import time
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient, MarketOutcome, derive_market_pda

def main():
    client = ProphetClient()
    
    oracle_path = os.getenv("ORACLE_KEYPAIR_PATH")
    if not oracle_path:
        print("ORACLE_KEYPAIR_PATH missing")
        return
        
    with open(oracle_path, 'r') as f:
        import json
        oracle_kp = Keypair.from_bytes(bytes(json.loads(f.read().strip())))

    relayer_kp = client.payer

    market_env = os.getenv("MARKET_PUBKEY", "").strip()
    resolver_hash_hex = os.getenv("RESOLVER_HASH_HEX", "").strip()
    open_ts_str = os.getenv("OPEN_TS", "").strip()

    if market_env:
        market_pda = Pubkey.from_string(market_env)
        if not resolver_hash_hex or not open_ts_str:
            print("When MARKET_PUBKEY is set, RESOLVER_HASH_HEX and OPEN_TS are also required.")
            return
        resolver_hash = bytes.fromhex(resolver_hash_hex)
        open_ts = int(open_ts_str)
    else:
        resolver_hash = bytes([1] * 32)
        open_ts = int(time.time()) - 1000
        market_pda, _ = derive_market_pda(resolver_hash, open_ts, client.program_id)
        print("WARN: using synthetic market PDA. Set MARKET_PUBKEY/RESOLVER_HASH_HEX/OPEN_TS for real runs.")
    
    print(f"Resolving legacy single-oracle market {market_pda} via signed message...")
    
    try:
        sig = client.resolve_market_signed(
            market=market_pda,
            resolver_hash=resolver_hash,
            open_ts=open_ts,
            oracle_keypair=oracle_kp,
            outcome=MarketOutcome.Yes,
            proof_hash=bytes([0]*32),
            public_inputs_hash=bytes([0]*32),
            relayer_keypair=relayer_kp
        )
        print(f"Legacy compatibility resolve succeeded: {sig}")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    main()
