import os
import sys
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient

def main():
    if len(sys.argv) < 7:
        print("Args missing")
        return

    client = ProphetClient()
    market = Pubkey.from_string(sys.argv[1])
    order_yes = Pubkey.from_string(sys.argv[2])
    order_no = Pubkey.from_string(sys.argv[3])
    owner_yes = Pubkey.from_string(sys.argv[4])
    owner_no = Pubkey.from_string(sys.argv[5])
    max_qty = int(sys.argv[6])
    quote_mint = Pubkey.from_string(os.getenv("QUOTE_MINT", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"))

    print("Submitting match...")
    try:
        sig = client.match_orders(
            market=market,
            order_yes=order_yes,
            order_no=order_no,
            owner_yes=owner_yes,
            owner_no=owner_no,
            quote_mint=quote_mint,
            max_qty_atoms=max_qty
        )
        print(f"Matched: {sig}")
    except Exception as e:
        print(f"Match failed: {e}")

if __name__ == "__main__":
    main()