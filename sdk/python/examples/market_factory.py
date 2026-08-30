import os
import sys
import time
import argparse
import json
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient, derive_market_pda
from prophet_sdk import resolver_v2
from prophet_sdk.resolver_hash import load_resolver_definition
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../apps/oracle-attester")))
from src.resolver_support import preflight_operated_resolver

def main():
    parser = argparse.ArgumentParser(description="Create Markets from Resolver Def")
    parser.add_argument("--resolver-file", required=True)
    parser.add_argument("--quote-mint", required=True)
    parser.add_argument("--notary-config", required=True)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--spacing-s", type=int, default=60)
    parser.add_argument("--open-delay-s", type=int, default=5)
    parser.add_argument("--lock-after-s", type=int, default=55)
    parser.add_argument("--resolve-after-s", type=int, default=55)
    parser.add_argument("--out", default="markets.jsonl")
    args = parser.parse_args()

    client = ProphetClient()
    resolver_def = load_resolver_definition(args.resolver_file)
    resolver_hash = resolver_v2.resolver_definition_hash(resolver_def)
    enabled = tuple(item.strip() for item in os.getenv("OPERATED_RESOLVER_TYPES", "").split(",") if item.strip())
    verifier_types = tuple(item.strip() for item in os.getenv("OPERATED_VERIFIER_TYPES", "").split(",") if item.strip())
    if not enabled or not verifier_types:
        raise ValueError("OPERATED_RESOLVER_TYPES and OPERATED_VERIFIER_TYPES must explicitly name the deployed V2 runtime")
    preflight_operated_resolver(
        resolver_hash,
        load_definition=lambda _hash: resolver_def,
        enabled_resolver_types=enabled,
        verifier_implementations={item: True for item in verifier_types},
    )
    resolver_hash_hex = resolver_hash.hex()
    
    quote_mint = Pubkey.from_string(args.quote_mint)
    oracle_auth = client.payer.pubkey()
    notary_config = Pubkey.from_string(args.notary_config)
    
    try:
        slot = client.client.get_slot().value
        base_ts = client.client.get_block_time(slot).value or int(time.time())
    except:
        base_ts = int(time.time())
        
    print(f"Creating {args.count} markets based on time {base_ts}...")
    
    created = []
    
    for i in range(args.count):
        open_ts = base_ts + args.open_delay_s + (i * args.spacing_s)
        lock_ts = open_ts + args.lock_after_s
        resolve_ts = open_ts + args.resolve_after_s
        if resolve_ts < lock_ts: resolve_ts = lock_ts
        
        try:
            sig = client.initialize_market_v2(
                resolver_hash=resolver_hash,
                open_ts=open_ts,
                market_nonce=i,
                lock_ts=lock_ts,
                resolve_ts=resolve_ts,
                notary_config=notary_config,
                oracle_authority=oracle_auth,
                quote_mint=quote_mint,
            )
            
            market_pda, _ = derive_market_pda(client.payer.pubkey(), resolver_hash, open_ts, i, client.program_id)
            print(f"[{i+1}/{args.count}] Created {market_pda} (Tx: {sig})")
            
            entry = {
                "market": str(market_pda),
                "resolver_hash_hex": resolver_hash_hex,
                "open_ts": open_ts,
                "lock_ts": lock_ts,
                "resolve_ts": resolve_ts,
                "quote_mint": str(quote_mint),
                "oracle": str(oracle_auth),
                "notary_config": str(notary_config),
                "mode": "v2",
            }
            created.append(entry)
            
        except Exception as e:
            print(f"Failed to create market {i}: {e}")
            
    with open(args.out, 'w') as f:
        for entry in created:
            f.write(json.dumps(entry) + "\n")
            
    print(f"Done. Wrote {len(created)} markets to {args.out}")

if __name__ == "__main__":
    main()
