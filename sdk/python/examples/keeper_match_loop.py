import time
import argparse
import asyncio
import logging
from typing import Dict, List, Optional
from solders.pubkey import Pubkey
from solana.rpc.websocket_api import connect
from solana.rpc.types import MemcmpOpts
from solana.rpc.commitment import Confirmed

from prophet_sdk import ProphetClient, OrderSide
from prophet_sdk.types import OrderAccount
from prophet_sdk.accounts import decode_order, extract_account_bytes
from prophet_sdk.client import ORDER_DISCRIMINATOR

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("keeper")

class OrderBook:
    def __init__(self):
        self.orders: Dict[str, OrderAccount] = {}
        self.lock = asyncio.Lock()

    async def update(self, pubkey_str: str, order: Optional[OrderAccount]):
        async with self.lock:
            if order and order.qty_remaining_atoms > 0:
                self.orders[pubkey_str] = order
            else:
                self.orders.pop(pubkey_str, None)

    async def replace_all(self, fresh_orders: List):
        async with self.lock:
            self.orders.clear()
            for pk, o in fresh_orders:
                self.orders[str(pk)] = o

    async def get_best_match(self) -> tuple[Optional[tuple], Optional[tuple]]:
        async with self.lock:
            buy_yes = []
            buy_no = []
            
            for pk_str, o in self.orders.items():
                if o.side == OrderSide.BuyYes:
                    buy_yes.append((pk_str, o))
                else:
                    buy_no.append((pk_str, o))
            
            if not buy_yes or not buy_no:
                return None, None

            best_bid = max(buy_yes, key=lambda x: (x[1].limit_p_yes_e8, -x[1].seq))
            best_ask = min(buy_no, key=lambda x: (x[1].limit_p_yes_e8, x[1].seq))
            
            return best_bid, best_ask

def parse_program_notification(msg) -> tuple[Optional[str], Optional[object]]:
    try:
        val = None
        if hasattr(msg, "value"):
            val = msg.value
        elif hasattr(msg, "result") and hasattr(msg.result, "value"):
            val = msg.result.value
        elif isinstance(msg, list) and len(msg) > 0:
             return parse_program_notification(msg[0])
        elif isinstance(msg, dict):
             if "params" in msg and "result" in msg["params"]:
                 val = msg["params"]["result"]["value"]
             elif "value" in msg:
                 val = msg["value"]

        if val is None:
            return None, None

        pubkey = None
        account = None

        if isinstance(val, dict):
            pubkey = val.get("pubkey")
            account = val.get("account")
        else:
            if hasattr(val, "pubkey"): pubkey = str(val.pubkey)
            if hasattr(val, "account"): account = val.account

        return pubkey, account

    except Exception:
        return None, None

async def run_ws_mode(
    client: ProphetClient, 
    market: Pubkey, 
    ws_url: str, 
    poll_ms: int, 
    max_qty: int, 
    max_matches: int,
    cu_limit: Optional[int], 
    cu_price: Optional[int]
):
    logger.info(f"Starting WS Keeper. Market: {market}. WS: {ws_url}")
    orderbook = OrderBook()
    
    logger.info("Fetching initial snapshot...")
    snapshot = client.fetch_orders_for_market(market)
    await orderbook.replace_all(snapshot)
    logger.info(f"Loaded {len(snapshot)} orders.")

    async def listener_task():
        while True:
            try:
                async with connect(ws_url) as ws:
                    logger.info("WebSocket connected.")
                    
                    filters = [
                        MemcmpOpts(offset=8, bytes=str(market)),
                        136,
                    ]
                    
                    await ws.program_subscribe(
                        client.program_id,
                        encoding="base64",
                        commitment=Confirmed,
                        filters=filters
                    )
                    
                    async for msg in ws:
                        pk_str, acc_info = parse_program_notification(msg)
                        
                        if not pk_str:
                            continue
                            
                        try:
                            data_obj = None
                            if acc_info is not None:
                                if hasattr(acc_info, "data"):
                                    data_obj = acc_info.data
                                elif isinstance(acc_info, dict) and "data" in acc_info:
                                    data_obj = acc_info["data"]

                            if not data_obj:
                                await orderbook.update(pk_str, None)
                                continue

                            raw_bytes = extract_account_bytes(data_obj)
                            
                            if len(raw_bytes) < 8 or raw_bytes[:8] != ORDER_DISCRIMINATOR:
                                await orderbook.update(pk_str, None)
                                continue
                                
                            order = decode_order(raw_bytes)
                            await orderbook.update(pk_str, order)
                            
                        except Exception:
                            await orderbook.update(pk_str, None)

            except Exception as e:
                logger.error(f"WS Listener error: {e}. Reconnecting in 5s...")
                await asyncio.sleep(5)

    async def matching_task():
        last_resync = time.time()
        m_acc = client.fetch_market(market)
        if not m_acc:
            logger.error("Market not found")
            return
        
        while True:
            if time.time() - last_resync > 60:
                logger.info("Periodic resync...")
                try:
                    snap = client.fetch_orders_for_market(market)
                    await orderbook.replace_all(snap)
                    last_resync = time.time()
                except Exception as e:
                    logger.warning(f"Resync failed: {e}")

            matched_any = False
            for _ in range(max_matches):
                bid, ask = await orderbook.get_best_match()
                if not bid or not ask:
                    break
                
                bid_pk_str, bid_order = bid
                ask_pk_str, ask_order = ask
                
                if bid_order.limit_p_yes_e8 < ask_order.limit_p_yes_e8:
                    break
                
                logger.info(f"Match: Bid {bid_order.limit_p_yes_e8} vs Ask {ask_order.limit_p_yes_e8}")
                
                try:
                    loop = asyncio.get_running_loop()
                    sig = await loop.run_in_executor(
                        None, 
                        lambda: client.match_orders(
                            market=market,
                            order_yes=Pubkey.from_string(bid_pk_str),
                            order_no=Pubkey.from_string(ask_pk_str),
                            owner_yes=bid_order.owner,
                            owner_no=ask_order.owner,
                            quote_mint=m_acc.quote_mint,
                            max_qty_atoms=max_qty,
                            compute_unit_limit=cu_limit,
                            compute_unit_price_micro_lamports=cu_price
                        )
                    )
                    logger.info(f"  Success: {sig}")
                    matched_any = True
                    
                except Exception as e:
                    msg = str(e).lower()
                    if any(x in msg for x in ["nocross", "do not cross", "account does not exist"]):
                        logger.info("  State changed, refreshing...")
                        await orderbook.update(bid_pk_str, None)
                        await orderbook.update(ask_pk_str, None)
                        break
                    else:
                        logger.error(f"  Match Error: {e}")
                        await asyncio.sleep(1)
                        break
            
            if not matched_any:
                await asyncio.sleep(poll_ms / 1000.0)
            else:
                await asyncio.sleep(0.05)

    await asyncio.gather(listener_task(), matching_task())

def run_poll_mode(
    client: ProphetClient, 
    market: Pubkey, 
    poll_ms: int, 
    max_qty: int, 
    max_matches: int,
    cu_limit: Optional[int], 
    cu_price: Optional[int]
):
    logger.info(f"Starting Poll Keeper. Market: {market}")
    
    m_acc = client.fetch_market(market)
    if not m_acc:
        print("Market not found")
        return
    quote_mint = m_acc.quote_mint
    
    while True:
        try:
            matched_any = False
            for _ in range(max_matches):
                orders = client.fetch_orders_for_market(market)
                buy_yes = []
                buy_no = []
                
                for pk, o in orders:
                    if o.side == OrderSide.BuyYes:
                        buy_yes.append((pk, o))
                    else:
                        buy_no.append((pk, o))
                
                if not buy_yes or not buy_no:
                    break
                    
                best_bid = max(buy_yes, key=lambda x: (x[1].limit_p_yes_e8, -x[1].seq))
                best_ask = min(buy_no, key=lambda x: (x[1].limit_p_yes_e8, x[1].seq))
                
                bid_pk, bid_order = best_bid
                ask_pk, ask_order = best_ask
                
                if bid_order.limit_p_yes_e8 < ask_order.limit_p_yes_e8:
                    break
                
                print(f"Match Attempt: Bid {bid_order.limit_p_yes_e8} vs Ask {ask_order.limit_p_yes_e8}")
                
                try:
                    sig = client.match_orders(
                        market=market,
                        order_yes=bid_pk,
                        order_no=ask_pk,
                        owner_yes=bid_order.owner,
                        owner_no=ask_order.owner,
                        quote_mint=quote_mint,
                        max_qty_atoms=max_qty,
                        compute_unit_limit=cu_limit,
                        compute_unit_price_micro_lamports=cu_price
                    )
                    print(f"  Success: {sig}")
                    matched_any = True
                    continue
                except Exception as e:
                    msg = str(e).lower()
                    if any(x in msg for x in ["nocross", "do not cross", "account does not exist"]):
                        print("  State changed, refetching...")
                        break
                    else:
                        print(f"  Error: {e}")
                        time.sleep(1)
                        break
            
            if not matched_any:
                time.sleep(poll_ms / 1000.0)
            else:
                time.sleep(0.05)
                
        except Exception as e:
            print(f"Loop error: {e}")
            time.sleep(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("market", help="Market Pubkey")
    parser.add_argument("--mode", choices=["poll", "ws"], default="poll")
    parser.add_argument("--ws-url", help="WebSocket URL (optional)")
    parser.add_argument("--poll-ms", type=int, default=1000)
    parser.add_argument("--max-qty", type=int, default=1000000)
    parser.add_argument("--max-matches", type=int, default=5)
    parser.add_argument("--cu-limit", type=int, default=None)
    parser.add_argument("--cu-price", type=int, default=None)
    args = parser.parse_args()
    
    client = ProphetClient()
    market = Pubkey.from_string(args.market)
    
    if args.mode == "ws":
        ws_url = args.ws_url
        if not ws_url:
            rpc = client.rpc_url
            if rpc.startswith("http://"):
                ws_url = rpc.replace("http://", "ws://")
                if ":8899" in ws_url:
                    ws_url = ws_url.replace(":8899", ":8900")
            elif rpc.startswith("https://"):
                ws_url = rpc.replace("https://", "wss://")
        
        try:
            asyncio.run(run_ws_mode(
                client, market, ws_url, args.poll_ms, args.max_qty, args.max_matches, args.cu_limit, args.cu_price
            ))
        except KeyboardInterrupt:
            pass
    else:
        run_poll_mode(
            client, market, args.poll_ms, args.max_qty, args.max_matches, args.cu_limit, args.cu_price
        )

if __name__ == "__main__":
    main()
