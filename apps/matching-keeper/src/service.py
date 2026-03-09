from __future__ import annotations

import asyncio
import logging
import time
from contextlib import suppress
from typing import Dict, List, Optional

from solders.pubkey import Pubkey
from solana.rpc.commitment import Confirmed
from solana.rpc.websocket_api import connect

from prophet_sdk import ProphetClient
from prophet_sdk.events import decode_anchor_event

from .config import Settings
from .engine import MatchingEngine
from .storage import SQLiteStateStore

logger = logging.getLogger("matching-keeper")

STATE_MISMATCH_ERRORS = (
    "nocross",
    "do not cross",
    "account does not exist",
    "invalid market stage",
    "market is already resolved",
)


def _extract_logs(msg) -> List[str]:
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
        if val is None:
            return []
        if hasattr(val, "logs"):
            return list(val.logs)
        if isinstance(val, dict):
            return list(val.get("logs", []))
        return []
    except Exception:
        return []


class MatchingKeeperService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.settings.validate_runtime()
        self.settings.ensure_runtime_dirs()
        self.client = ProphetClient(
            rpc_url=settings.RPC_URL,
            payer_keypair_path=settings.PAYER_KEYPAIR_PATH,
            program_id=settings.PROPHET_PROGRAM_ID,
        )
        self.store = SQLiteStateStore(settings.DB_PATH)
        self.engine = MatchingEngine()
        self.markets = list(settings.tracked_markets)
        self.market_set = set(self.markets)
        self._tasks: List[asyncio.Task] = []
        self._stopped = False
        self.started_at = 0
        self.last_ws_connect_at = 0
        self.last_ws_message_at = 0
        self.last_listener_error = ""
        self.last_matcher_error = ""

    async def start(self) -> None:
        if self._tasks:
            return
        self.store.init()
        self.started_at = int(time.time())
        await self.bootstrap()
        self._tasks = [
            asyncio.create_task(self._listener_loop(), name="matching-keeper-listener"),
            asyncio.create_task(self._matcher_loop(), name="matching-keeper-matcher"),
        ]

    async def stop(self) -> None:
        self._stopped = True
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with suppress(asyncio.CancelledError):
                await task
        self._tasks = []

    async def bootstrap(self) -> None:
        for market in self.markets:
            await self.refresh_market_snapshot(market)

    async def refresh_market_snapshot(self, market: Pubkey) -> None:
        loop = asyncio.get_running_loop()
        try:
            market_acc = await loop.run_in_executor(None, self.client.fetch_market, market)
            if market_acc is None:
                raise ValueError(f"Market {market} not found")
            orders = await loop.run_in_executor(None, self.client.fetch_orders_for_market, market)
            self.engine.ensure_market(market)
            self.engine.set_quote_mint(market, market_acc.quote_mint)
            self.engine.replace_orders(market, orders)
            self.store.replace_market_snapshot(market, market_acc.quote_mint, orders)
            logger.info("snapshot refreshed market=%s orders=%s", market, len(orders))
        except Exception as exc:
            error = str(exc)
            self.engine.note_sync_error(market, error)
            self.store.set_market_error(market, error)
            logger.warning("snapshot refresh failed market=%s error=%s", market, error)

    async def _apply_dirty_updates(self, market: Pubkey) -> None:
        dirty = self.engine.pop_dirty(market)
        if not dirty:
            return
        loop = asyncio.get_running_loop()
        updates: Dict[Pubkey, Optional[object]] = await loop.run_in_executor(
            None, self.client.fetch_orders_bulk, dirty
        )
        self.engine.apply_order_updates(market, updates)
        self.store.apply_order_updates(market, updates)

    async def _listener_loop(self) -> None:
        while not self._stopped:
            try:
                async with connect(self.settings.ws_url_effective) as ws:
                    self.last_ws_connect_at = int(time.time())
                    logger.info("logs websocket connected url=%s", self.settings.ws_url_effective)
                    await ws.logs_subscribe(
                        filter_={"mentions": [str(self.client.program_id)]},
                        commitment=Confirmed,
                    )
                    async for msg in ws:
                        if self._stopped:
                            return
                        self.last_ws_message_at = int(time.time())
                        for line in _extract_logs(msg):
                            if not line.startswith("Program data: "):
                                continue
                            event = decode_anchor_event(line[len("Program data: ") :])
                            if event is None or event.market not in self.market_set:
                                continue
                            for order_pubkey in event.order_pubkeys:
                                self.engine.mark_dirty(event.market, order_pubkey)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_listener_error = str(exc)
                logger.error("listener loop error=%s", exc)
                await asyncio.sleep(5)

    async def _matcher_loop(self) -> None:
        loop = asyncio.get_running_loop()
        last_resync = 0
        while not self._stopped:
            try:
                matched_any = False
                if time.time() - last_resync >= self.settings.SNAPSHOT_RESYNC_S:
                    for market in self.markets:
                        await self.refresh_market_snapshot(market)
                    last_resync = time.time()

                for market in self.markets:
                    await self._apply_dirty_updates(market)
                    for _ in range(self.settings.MAX_MATCHES_PER_MARKET):
                        candidate = self.engine.best_crossed_match(market, self.settings.MAX_QTY_ATOMS)
                        if candidate is None:
                            break
                        runtime = self.engine.market_snapshot(market)
                        quote_mint = runtime["quote_mint"]
                        if not quote_mint:
                            break
                        try:
                            signature = await loop.run_in_executor(
                                None,
                                lambda c=candidate, q=Pubkey.from_string(quote_mint): self.client.match_orders(
                                    market=c.market,
                                    order_yes=c.order_yes_pubkey,
                                    order_no=c.order_no_pubkey,
                                    owner_yes=c.order_yes.owner,
                                    owner_no=c.order_no.owner,
                                    quote_mint=q,
                                    max_qty_atoms=c.qty_atoms,
                                    compute_unit_limit=self.settings.COMPUTE_UNIT_LIMIT,
                                    compute_unit_price_micro_lamports=self.settings.COMPUTE_UNIT_PRICE_MICRO_LAMPORTS,
                                ),
                            )
                            logger.info(
                                "match success market=%s yes=%s no=%s qty=%s sig=%s",
                                market,
                                candidate.order_yes_pubkey,
                                candidate.order_no_pubkey,
                                candidate.qty_atoms,
                                signature,
                            )
                            self.store.record_match_attempt(
                                market=market,
                                order_yes=candidate.order_yes_pubkey,
                                order_no=candidate.order_no_pubkey,
                                qty_atoms=candidate.qty_atoms,
                                success=True,
                                signature=signature,
                            )
                            self.engine.note_match_result(market, signature=signature)
                            self.engine.mark_dirty(market, candidate.order_yes_pubkey)
                            self.engine.mark_dirty(market, candidate.order_no_pubkey)
                            await self._apply_dirty_updates(market)
                            matched_any = True
                        except Exception as exc:
                            error = str(exc)
                            self.store.record_match_attempt(
                                market=market,
                                order_yes=candidate.order_yes_pubkey,
                                order_no=candidate.order_no_pubkey,
                                qty_atoms=candidate.qty_atoms,
                                success=False,
                                error_text=error,
                            )
                            self.engine.note_match_result(market, error=error)
                            lowered = error.lower()
                            if any(token in lowered for token in STATE_MISMATCH_ERRORS):
                                self.engine.mark_dirty(market, candidate.order_yes_pubkey)
                                self.engine.mark_dirty(market, candidate.order_no_pubkey)
                                await self._apply_dirty_updates(market)
                                logger.info("state mismatch refreshed market=%s error=%s", market, error)
                            else:
                                logger.error("match failed market=%s error=%s", market, error)
                            break

                if matched_any:
                    await asyncio.sleep(0.05)
                else:
                    await asyncio.sleep(self.settings.POLL_MS / 1000.0)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_matcher_error = str(exc)
                logger.error("matcher loop error=%s", exc)
                await asyncio.sleep(1)

    def health(self) -> dict:
        now = int(time.time())
        return {
            "ok": not self._stopped,
            "started_at": self.started_at,
            "rpc_url": self.settings.RPC_URL,
            "ws_url": self.settings.ws_url_effective,
            "tracked_markets": [str(market) for market in self.markets],
            "last_ws_connect_at": self.last_ws_connect_at,
            "last_ws_message_at": self.last_ws_message_at,
            "last_ws_message_age_s": (now - self.last_ws_message_at) if self.last_ws_message_at else None,
            "last_listener_error": self.last_listener_error,
            "last_matcher_error": self.last_matcher_error,
        }

    def market_statuses(self) -> List[dict]:
        persisted = {row["market"]: row for row in self.store.list_market_statuses()}
        merged = []
        for runtime in self.engine.all_market_snapshots():
            stored = persisted.get(runtime["market"], {})
            merged.append(
                {
                    **runtime,
                    "stored_open_orders": stored.get("open_orders", 0),
                    "stored_last_snapshot_at": stored.get("last_snapshot_at", 0),
                    "stored_last_error": stored.get("last_error", ""),
                }
            )
        return merged

    def recent_attempts(self, limit: int = 50) -> List[dict]:
        return self.store.list_recent_match_attempts(limit=limit)
