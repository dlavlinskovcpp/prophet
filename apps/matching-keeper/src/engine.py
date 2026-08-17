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
    market_status: str = ""
    discovery_source: str = ""
    active: bool = True
    last_seen_at: int = 0
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

    def activate_market(self, market: Pubkey, *, discovery_source: str, seen_at: Optional[int] = None) -> None:
        self.ensure_market(market)
        runtime = self._markets[market]
        runtime.discovery_source = discovery_source
        runtime.active = True
        runtime.last_seen_at = int(seen_at or time.time())

    def retire_market(
        self,
        market: Pubkey,
        *,
        market_status: Optional[str] = None,
        discovery_source: Optional[str] = None,
        error: str = "",
        seen_at: Optional[int] = None,
    ) -> None:
        self.ensure_market(market)
        runtime = self._markets[market]
        if market_status is not None:
            runtime.market_status = market_status
        if discovery_source is not None:
            runtime.discovery_source = discovery_source
        runtime.active = False
        runtime.dirty_orders.clear()
        runtime.orders.clear()
        runtime.last_seen_at = int(seen_at or time.time())
        if error:
            runtime.last_error = error

    def set_quote_mint(self, market: Pubkey, quote_mint: Pubkey) -> None:
        self.ensure_market(market)
        self._markets[market].quote_mint = quote_mint

    def set_market_metadata(
        self,
        market: Pubkey,
        *,
        quote_mint: Optional[Pubkey],
        market_status: str,
        discovery_source: str,
        seen_at: Optional[int] = None,
    ) -> None:
        self.ensure_market(market)
        runtime = self._markets[market]
        runtime.quote_mint = quote_mint
        runtime.market_status = market_status
        runtime.discovery_source = discovery_source
        runtime.active = True
        runtime.last_seen_at = int(seen_at or time.time())

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

        top_yes_pubkey, top_yes = buy_yes[0]
        top_no_pubkey, top_no = buy_no[0]

        if top_yes.limit_p_yes_e8 < top_no.limit_p_yes_e8:
            return None

        selected = None
        if top_yes.owner != top_no.owner:
            selected = (top_yes_pubkey, top_yes, top_no_pubkey, top_no)
        else:
            # Let the shared top owner be O. For any valid later pair (Yi, Nj):
            # if Yi.owner != O then (Yi, N0) is also distinct-owner and at least
            # as crossed because N0 has no worse NO price; otherwise Nj.owner != O
            # and (Y0, Nj) is distinct-owner and at least as crossed because Y0
            # has no worse YES price. So a best valid pair always exists on one
            # of these two top-of-book frontiers; no Cartesian scan is required.
            yes_frontier_open = True
            no_frontier_open = True
            for depth in range(1, max(len(buy_yes), len(buy_no))):
                if no_frontier_open and depth < len(buy_no):
                    order_no_pubkey, order_no = buy_no[depth]
                    if order_no.owner != top_yes.owner:
                        no_frontier_open = False
                        if top_yes.limit_p_yes_e8 >= order_no.limit_p_yes_e8:
                            selected = (top_yes_pubkey, top_yes, order_no_pubkey, order_no)
                            break

                if yes_frontier_open and depth < len(buy_yes):
                    order_yes_pubkey, order_yes = buy_yes[depth]
                    if order_yes.owner != top_no.owner:
                        yes_frontier_open = False
                        if order_yes.limit_p_yes_e8 >= top_no.limit_p_yes_e8:
                            selected = (order_yes_pubkey, order_yes, top_no_pubkey, top_no)
                            break

                if not yes_frontier_open and not no_frontier_open:
                    break

        if selected is None:
            return None

        order_yes_pubkey, order_yes, order_no_pubkey, order_no = selected
        if order_yes.owner == order_no.owner:
            raise AssertionError("matching engine selected a self-match")

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

    def find_market_for_order(self, order_pubkey: Pubkey) -> Optional[Pubkey]:
        for market, runtime in self._markets.items():
            if order_pubkey in runtime.orders:
                return market
        return None

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
            "market_status": runtime.market_status,
            "discovery_source": runtime.discovery_source,
            "active": runtime.active,
            "last_seen_at": runtime.last_seen_at,
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
