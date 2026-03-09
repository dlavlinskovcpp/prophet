import os
import sys
import time
import argparse
import json
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient, derive_market_pda
from prophet_sdk.resolver_hash import compute_resolver_hash, load_resolver_definition

def main():
    parser = argparse.ArgumentParser(description="Create Markets from Resolver Def")
    parser.add_argument("--resolver-file", required=True)
    parser.add_argument("--quote-mint", required=True)
    parser.add_argument("--notary-config", default="")
    parser.add_argument("--oracle", default="")
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--spacing-s", type=int, default=60)
    parser.add_argument("--open-delay-s", type=int, default=5)
    parser.add_argument("--lock-after-s", type=int, default=55)
    parser.add_argument("--resolve-after-s", type=int, default=55)
    parser.add_argument("--out", default="markets.jsonl")
    args = parser.parse_args()

    client = ProphetClient()
    resolver_def = load_resolver_definition(args.resolver_file)
    resolver_hash = compute_resolver_hash(resolver_def)
    resolver_hash_hex = resolver_hash.hex()
    
    quote_mint = Pubkey.from_string(args.quote_mint)
    oracle_auth = Pubkey.from_string(args.oracle) if args.oracle else client.payer.pubkey()
    notary_config = Pubkey.from_string(args.notary_config) if args.notary_config else None
    
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
            if args.legacy:
                if not args.oracle:
                    raise ValueError("--oracle is required when --legacy is set")
                sig = client.initialize_market(
                    resolver_hash=resolver_hash,
                    open_ts=open_ts,
                    lock_ts=lock_ts,
                    resolve_ts=resolve_ts,
                    oracle_authority=oracle_auth,
                    quote_mint=quote_mint,
                )
            else:
                if not notary_config:
                    raise ValueError("v2 market creation requires --notary-config. Use --legacy --oracle for compatibility mode.")
                sig = client.initialize_market_v2(
                    resolver_hash=resolver_hash,
                    open_ts=open_ts,
                    lock_ts=lock_ts,
                    resolve_ts=resolve_ts,
                    notary_config=notary_config,
                    oracle_authority=oracle_auth,
                    quote_mint=quote_mint,
                )
            
            market_pda, _ = derive_market_pda(resolver_hash, open_ts, client.program_id)
            print(f"[{i+1}/{args.count}] Created {market_pda} (Tx: {sig})")
            
            entry = {
                "market": str(market_pda),
                "resolver_hash_hex": resolver_hash_hex,
                "open_ts": open_ts,
                "lock_ts": lock_ts,
                "resolve_ts": resolve_ts,
                "quote_mint": str(quote_mint),
                "oracle": str(oracle_auth),
                "notary_config": str(notary_config) if notary_config else "",
                "mode": "legacy" if args.legacy else "v2",
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
