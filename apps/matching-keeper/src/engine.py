from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from solders.pubkey import Pubkey

from prophet_sdk import OrderSide
from prophet_sdk.types import OrderAccount


@dataclass
class MatchCandidate:
    market: Pubkey
    order_yes_pubkey: Pubkey
    order_no_pubkey: Pubkey
    order_yes: OrderAccount
    order_no: OrderAccount
    qty_atoms: int


@dataclass
class MarketRuntimeState:
    quote_mint: Optional[Pubkey] = None
    orders: Dict[Pubkey, OrderAccount] = field(default_factory=dict)
    dirty_orders: Set[Pubkey] = field(default_factory=set)
    last_snapshot_at: int = 0
    last_match_at: int = 0
    last_match_signature: str = ""
    last_error: str = ""


class MatchingEngine:
    def __init__(self) -> None:
        self._markets: Dict[Pubkey, MarketRuntimeState] = {}

    def ensure_market(self, market: Pubkey) -> None:
        self._markets.setdefault(market, MarketRuntimeState())

    def set_quote_mint(self, market: Pubkey, quote_mint: Pubkey) -> None:
        self.ensure_market(market)
        self._markets[market].quote_mint = quote_mint

    def replace_orders(self, market: Pubkey, orders: List[tuple[Pubkey, OrderAccount]]) -> None:
        self.ensure_market(market)
        runtime = self._markets[market]
        runtime.orders = {pk: order for pk, order in orders if order.qty_remaining_atoms > 0}
        runtime.dirty_orders.clear()
        runtime.last_snapshot_at = int(time.time())
        runtime.last_error = ""

    def apply_order_updates(self, market: Pubkey, updates: Dict[Pubkey, Optional[OrderAccount]]) -> None:
        self.ensure_market(market)
        runtime = self._markets[market]
        for pk, order in updates.items():
            if order is None or order.qty_remaining_atoms <= 0:
                runtime.orders.pop(pk, None)
            else:
                runtime.orders[pk] = order
            runtime.dirty_orders.discard(pk)
        runtime.last_snapshot_at = int(time.time())

    def mark_dirty(self, market: Pubkey, order_pubkey: Pubkey) -> None:
        self.ensure_market(market)
        self._markets[market].dirty_orders.add(order_pubkey)

    def pop_dirty(self, market: Pubkey) -> List[Pubkey]:
        self.ensure_market(market)
        runtime = self._markets[market]
        dirty = list(runtime.dirty_orders)
        runtime.dirty_orders.clear()
        return dirty

    def best_crossed_match(self, market: Pubkey, max_qty_atoms: int) -> Optional[MatchCandidate]:
        self.ensure_market(market)
        runtime = self._markets[market]
        buy_yes = []
        buy_no = []

        for pk, order in runtime.orders.items():
            if order.qty_remaining_atoms <= 0:
                continue
            if order.side == OrderSide.BuyYes:
                buy_yes.append((pk, order))
            else:
                buy_no.append((pk, order))

        if not buy_yes or not buy_no:
            return None

        buy_yes.sort(key=lambda item: (-item[1].limit_p_yes_e8, item[1].seq, bytes(item[0])))
        buy_no.sort(key=lambda item: (item[1].limit_p_yes_e8, item[1].seq, bytes(item[0])))

        order_yes_pubkey, order_yes = buy_yes[0]
        order_no_pubkey, order_no = buy_no[0]

        if order_yes.limit_p_yes_e8 < order_no.limit_p_yes_e8:
            return None

        qty_atoms = min(max_qty_atoms, int(order_yes.qty_remaining_atoms), int(order_no.qty_remaining_atoms))
        if qty_atoms <= 0:
            return None

        return MatchCandidate(
            market=market,
            order_yes_pubkey=order_yes_pubkey,
            order_no_pubkey=order_no_pubkey,
            order_yes=order_yes,
            order_no=order_no,
            qty_atoms=qty_atoms,
        )

    def note_match_result(self, market: Pubkey, signature: str = "", error: str = "") -> None:
        self.ensure_market(market)
        runtime = self._markets[market]
        runtime.last_match_at = int(time.time())
        runtime.last_match_signature = signature
        runtime.last_error = error

    def note_sync_error(self, market: Pubkey, error: str) -> None:
        self.ensure_market(market)
        self._markets[market].last_error = error

    def market_snapshot(self, market: Pubkey) -> dict:
        self.ensure_market(market)
        runtime = self._markets[market]
        buy_yes = 0
        buy_no = 0
        for order in runtime.orders.values():
            if order.side == OrderSide.BuyYes:
                buy_yes += 1
            else:
                buy_no += 1
        return {
            "market": str(market),
            "quote_mint": str(runtime.quote_mint) if runtime.quote_mint else "",
            "open_orders": len(runtime.orders),
            "buy_yes_orders": buy_yes,
            "buy_no_orders": buy_no,
            "dirty_orders": len(runtime.dirty_orders),
            "last_snapshot_at": runtime.last_snapshot_at,
            "last_match_at": runtime.last_match_at,
            "last_match_signature": runtime.last_match_signature,
            "last_error": runtime.last_error,
        }

    def all_market_snapshots(self) -> List[dict]:
        return [self.market_snapshot(market) for market in sorted(self._markets, key=bytes)]
