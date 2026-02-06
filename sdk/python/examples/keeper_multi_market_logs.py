from __future__ import annotations
import time
import argparse
import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple
from solders.pubkey import Pubkey
from solana.rpc.websocket_api import connect
from solana.rpc.commitment import Confirmed

from prophet_sdk import ProphetClient, OrderSide
from prophet_sdk.types import OrderAccount
from prophet_sdk.events import decode_anchor_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("multi-keeper")

class MultiMarketBook:
    def __init__(self):
        # Map: Market -> {Order -> OrderAccount}
        self.books: Dict[Pubkey, Dict[Pubkey, OrderAccount]] = {}
        # Map: Market -> Set[DirtyOrders]
        self.dirty: Dict[Pubkey, Set[Pubkey]] = {}
        self.lock = asyncio.Lock()
        self.quote_mints: Dict[Pubkey, Pubkey] = {}

    async def ensure_market(self, market: Pubkey):
        async with self.lock:
            if market not in self.books:
                self.books[market] = {}
                self.dirty[market] = set()

    async def set_quote_mint(self, market: Pubkey, mint: Pubkey):
        async with self.lock:
            self.quote_mints[market] = mint

    async def mark_dirty(self, market: Pubkey, order: Pubkey):
        async with self.lock:
            if market in self.dirty:
                self.dirty[market].add(order)

    async def pop_dirty_orders(self, market: Pubkey) -> List[Pubkey]:
        async with self.lock:
            s = self.dirty.get(market, set())
            self.dirty[market] = set()
            return list(s)

    async def replace_book(self, market: Pubkey, orders: List):
        async with self.lock:
            self.books[market] = {}
            for pk, o in orders:
                self.books[market][pk] = o

    async def update_orders(self, market: Pubkey, updated_map: Dict[Pubkey, Optional[OrderAccount]]):
        async with self.lock:
            if market not in self.books: return
            for pk, o in updated_map.items():
                if o:
                    self.books[market][pk] = o
                else:
                    self.books[market].pop(pk, None)

    async def get_snapshot(self, market: Pubkey) -> Tuple[List, List]:
        async with self.lock:
            orders = self.books.get(market, {})
            buy_yes = []
            buy_no = []
            for pk, o in orders.items():
                if o.side == OrderSide.BuyYes: buy_yes.append((pk, o))
                else: buy_no.append((pk, o))
            return buy_yes, buy_no

    async def get_quote_mint(self, market: Pubkey) -> Optional[Pubkey]:
        async with self.lock:
            return self.quote_mints.get(market)

def extract_logs(msg) -> List[str]:
    try:
        val = None
        if hasattr(msg, "value"):
            val = msg.value
        elif hasattr(msg, "result") and hasattr(msg.result, "value"):
            val = msg.result.value
        elif isinstance(msg, dict):
            if "params" in msg and "result" in msg["params"]:
                val = msg["params"]["result"]["value"]
            elif "value" in msg:
                val = msg["value"]
        
        if val is None: return []

        if hasattr(val, "logs"): return val.logs
        if isinstance(val, dict) and "logs" in val: return val["logs"]
        
        return []
    except:
        return []

async def run_keeper(
    markets: List[Pubkey],
    ws_url: str,
    poll_ms: int,
    max_qty: int,
    max_matches: int,
    cu_limit: Optional[int], 
    cu_price: Optional[int]
):
    client = ProphetClient()
    book = MultiMarketBook()
    
    markets_map = {str(m): m for m in markets}
    
    logger.info(f"Initializing for {len(markets)} markets...")
    
    # 1. Bootstrap
    for m in markets:
        await book.ensure_market(m)
        m_info = client.fetch_market(m)
        if m_info:
            await book.set_quote_mint(m, m_info.quote_mint)
        else:
            logger.warning(f"Market {m} not found (or fetch failed). Mint not set.")
            
        snap = client.fetch_orders_for_market(m)
        await book.replace_book(m, snap)
        logger.info(f"Loaded {len(snap)} orders for {m}")

    async def listener_task():
        while True:
            try:
                async with connect(ws_url) as ws:
                    logger.info("Logs WS connected.")
                    
                    # Using filter_ kwarg for compatibility
                    await ws.logs_subscribe(
                        filter_={"mentions": [str(client.program_id)]},
                        commitment=Confirmed
                    )
                    
                    async for msg in ws:
                        logs = extract_logs(msg)
                        if not logs: continue

                        for line in logs:
                            if line.startswith("Program data: "):
                                b64 = line[len("Program data: "):]
                                event = decode_anchor_event(b64)
                                if event:
                                    m_key = markets_map.get(str(event.market))
                                    if m_key:
                                        for o in event.order_pubkeys:
                                            await book.mark_dirty(m_key, o)

            except Exception as e:
                logger.error(f"WS Error: {e}. Retry in 5s...")
                await asyncio.sleep(5)

    async def matcher_task():
        last_full_resync = time.time()
        loop = asyncio.get_running_loop()
        
        while True:
            cycle_matched_any = False
            
            # Periodic Full Resync
            if time.time() - last_full_resync > 300:
                logger.info("Periodic full resync...")
                for m in markets:
                    try:
                        snap = await loop.run_in_executor(None, client.fetch_orders_for_market, m)
                        await book.replace_book(m, snap)
                    except: pass
                last_full_resync = time.time()

            # Round Robin Markets
            for m in markets:
                # 1. Process Dirty
                dirty_orders = await book.pop_dirty_orders(m)
                if dirty_orders:
                    updated_map = await loop.run_in_executor(None, client.fetch_orders_bulk, dirty_orders)
                    await book.update_orders(m, updated_map)

                # 2. Compute Matches
                quote_mint = await book.get_quote_mint(m)
                if not quote_mint: continue

                matches_attempted = 0
                while matches_attempted < max_matches:
                    buy_yes, buy_no = await book.get_snapshot(m)
                    
                    if not buy_yes or not buy_no:
                        break

                    buy_yes.sort(key=lambda x: (-x[1].limit_p_yes_e8, x[1].seq))
                    buy_no.sort(key=lambda x: (x[1].limit_p_yes_e8, x[1].seq))

                    bid_pk, bid_order = buy_yes[0]
                    ask_pk, ask_order = buy_no[0]

                    if bid_order.limit_p_yes_e8 < ask_order.limit_p_yes_e8:
                        break 

                    logger.info(f"[{m}] Match: Bid {bid_order.limit_p_yes_e8} vs Ask {ask_order.limit_p_yes_e8}")
                    
                    try:
                        sig = await loop.run_in_executor(
                            None,
                            lambda: client.match_orders(
                                market=m,
                                order_yes=bid_pk,
                                order_no=ask_pk,
                                owner_yes=bid_order.owner,
                                owner_no=ask_order.owner,
                                quote_mint=quote_mint,
                                max_qty_atoms=max_qty,
                                compute_unit_limit=cu_limit,
                                compute_unit_price_micro_lamports=cu_price
                            )
                        )
                        logger.info(f"  Success: {sig}")
                        
                        await book.mark_dirty(m, bid_pk)
                        await book.mark_dirty(m, ask_pk)
                        
                        updated_pair = await loop.run_in_executor(None, client.fetch_orders_bulk, [bid_pk, ask_pk])
                        await book.update_orders(m, updated_pair)
                        
                        matches_attempted += 1
                        cycle_matched_any = True

                    except Exception as e:
                        msg = str(e).lower()
                        if any(x in msg for x in ["nocross", "do not cross", "account does not exist"]):
                            logger.info(f"  State mismatch, marking dirty...")
                            await book.mark_dirty(m, bid_pk)
                            await book.mark_dirty(m, ask_pk)
                        else:
                            logger.error(f"Match failed: {e}")
                        break
            
            if cycle_matched_any:
                await asyncio.sleep(0.05)
            else:
                await asyncio.sleep(poll_ms / 1000.0)

    await asyncio.gather(listener_task(), matcher_task())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("markets", nargs="+", help="List of Market Pubkeys")
    parser.add_argument("--ws-url", required=True)
    parser.add_argument("--poll-ms", type=int, default=250)
    parser.add_argument("--max-qty", type=int, default=1000000)
    parser.add_argument("--max-matches", type=int, default=10)
    parser.add_argument("--cu-limit", type=int, default=None)
    parser.add_argument("--cu-price", type=int, default=None)
    args = parser.parse_args()

    markets = [Pubkey.from_string(m) for m in args.markets]
    
    try:
        asyncio.run(run_keeper(
            markets, args.ws_url, args.poll_ms, args.max_qty, args.max_matches, args.cu_limit, args.cu_price
        ))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()