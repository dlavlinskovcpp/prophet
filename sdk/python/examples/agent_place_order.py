import os
import time
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient, OrderSide, derive_market_pda

def main():
    client = ProphetClient()
    quote_mint = Pubkey.from_string(os.getenv("QUOTE_MINT", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")) 

    resolver_hash = bytes([1]*32)
    now = int(time.time())
    open_ts = now - 100
    market_pda, _ = derive_market_pda(resolver_hash, open_ts, client.program_id)
    
    print(f"Placing order on market {market_pda}...")
    try:
        sig = client.place_order(
            market=market_pda,
            order_seq=0,
            side=OrderSide.BuyYes,
            limit_p_yes_e8=50_000_000, 
            qty_atoms=1_000_000, 
            quote_mint=quote_mint
        )
        print(f"Order placed: {sig}")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    main()