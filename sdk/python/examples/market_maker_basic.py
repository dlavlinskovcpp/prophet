import os
import sys
import time
import argparse
import json
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient, OrderSide, MarketStatus

def main():
    parser = argparse.ArgumentParser(description="Basic Market Maker")
    parser.add_argument("--markets", required=True, help="Path to markets.jsonl")
    parser.add_argument("--quote-mint", required=True)
    parser.add_argument("--qty-atoms", type=int, default=100)
    parser.add_argument("--bid-e8", type=int, default=49000000)
    parser.add_argument("--ask-e8", type=int, default=51000000)
    parser.add_argument("--refresh-s", type=int, default=10)
    args = parser.parse_args()

    client = ProphetClient()
    target_mint = Pubkey.from_string(args.quote_mint)
    
    # State: market_pubkey_str -> {"yes_seq": int, "no_seq": int}
    state = {}
    
    # Load markets
    markets_to_make = []
    with open(args.markets, 'r') as f:
        for line in f:
            try:
                m = json.loads(line)
                if m.get("quote_mint") == str(target_mint):
                    markets_to_make.append(Pubkey.from_string(m["market"]))
            except: pass
            
    print(f" loaded {len(markets_to_make)} markets matching mint {target_mint}")

    while True:
        print(f"--- Refreshing Quotes ---")
        for m_pubkey in markets_to_make:
            try:
                # Use Chain Time
                try:
                    slot = client.client.get_slot().value
                    now = client.client.get_block_time(slot).value or int(time.time())
                except:
                    now = int(time.time())

                m_acc = client.fetch_market(m_pubkey)
                if not m_acc: continue
                
                if m_acc.status != MarketStatus.Open:
                    continue
                if now >= m_acc.lock_ts:
                    continue
                
                m_str = str(m_pubkey)
                current_orders = state.get(m_str, {})
                
                # Cancel old orders if they exist
                if "yes_seq" in current_orders:
                    try:
                        client.cancel_order_by_seq(m_pubkey, current_orders["yes_seq"])
                    except: pass
                if "no_seq" in current_orders:
                    try:
                        client.cancel_order_by_seq(m_pubkey, current_orders["no_seq"])
                    except: pass
                
                # Place new quotes using new helper that returns seq
                try:
                    yes_seq, _ = client.place_order_auto_seq_with_seq(
                        m_pubkey, OrderSide.BuyYes, args.bid_e8, args.qty_atoms, target_mint
                    )
                    current_orders["yes_seq"] = yes_seq
                    
                    no_seq, _ = client.place_order_auto_seq_with_seq(
                        m_pubkey, OrderSide.BuyNo, args.ask_e8, args.qty_atoms, target_mint
                    )
                    current_orders["no_seq"] = no_seq
                    
                    print(f"Quoted {m_str}: Yes({yes_seq})@{args.bid_e8} No({no_seq})@{args.ask_e8}")
                    state[m_str] = current_orders
                    
                except Exception as e:
                    print(f"Failed to quote {m_str}: {e}")

            except Exception as e:
                print(f"Error processing {m_pubkey}: {e}")
        
        time.sleep(args.refresh_s)

if __name__ == "__main__":
    main()