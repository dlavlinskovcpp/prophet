from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple

from solana.rpc.commitment import Confirmed
from solana.rpc.types import DataSizeOpts
from solana.rpc.websocket_api import connect
from solders.pubkey import Pubkey

from prophet_sdk import ProphetClient
from prophet_sdk.accounts import decode_order, extract_account_bytes
from prophet_sdk.client import ORDER_DISCRIMINATOR
from prophet_sdk.types import MarketAccount, MarketStatus, OrderAccount

from .config import Settings
from .engine import MatchingEngine
from .storage import SQLiteStateStore


logger = logging.getLogger(__name__)

ORDER_ACCOUNT_SIZE = 136
DEFAULT_MARKET_STATUS = "Unknown"


def _status_name(status: MarketStatus | int) -> str:
    try:
        return MarketStatus(int(status)).name
    except Exception:
        return str(int(status))


def _notification_account_value(message: object) -> Tuple[Optional[Pubkey], object]:
    try:
        value = None
        if hasattr(message, "value"):
            value = message.value
        elif hasattr(message, "result") and hasattr(message.result, "value"):
            value = message.result.value
        elif isinstance(message, list) and message:
            return _notification_account_value(message[0])
        elif isinstance(message, dict):
            if "params" in message and "result" in message["params"]:
                value = message["params"]["result"]["value"]
            elif "value" in message:
                value = message["value"]

        if value is None:
            return None, None

        pubkey_value = None
        account_value = None
        if isinstance(value, dict):
            pubkey_value = value.get("pubkey")
            account_value = value.get("account")
        else:
            if hasattr(value, "pubkey"):
                pubkey_value = str(value.pubkey)
            if hasattr(value, "account"):
                account_value = value.account

        if not pubkey_value:
            return None, account_value
        return Pubkey.from_string(str(pubkey_value)), account_value
    except Exception:
        return None, None


class MatchingKeeperService:
    def __init__(
        self,
        settings: Settings,
        *,
        client: Optional[ProphetClient] = None,
        engine: Optional[MatchingEngine] = None,
        store: Optional[SQLiteStateStore] = None,
    ) -> None:
        self.settings = settings
        self.client = client or ProphetClient(
            rpc_url=settings.RPC_URL,
            payer_keypair_path=settings.PAYER_KEYPAIR_PATH,
            program_id=settings.PROPHET_PROGRAM_ID,
        )
        self.engine = engine or MatchingEngine()
        self.store = store or SQLiteStateStore(settings.DB_PATH)

        self._running = False
        self._stop_event = asyncio.Event()
        self._tasks: List[asyncio.Task] = []
        self._market_sources: Dict[Pubkey, str] = {}

        self._last_ws_connected_at = 0
        self._last_ws_message_at = 0
        self._last_ws_error = ""
        self._last_discovery_at = 0
        self._last_discovery_error = ""
        self._last_prune_at = 0
        self._last_pruned_attempts = 0

    async def start(self) -> None:
        if self._running:
            return

        self.settings.validate_runtime()
        self.settings.ensure_runtime_dirs()
        self.store.init()
        self._running = True
        self._stop_event.clear()

        await self._run_discovery_cycle()
        await self._run_prune_cycle()

        self._tasks = [
            asyncio.create_task(self._listener_loop(), name="matching-keeper-listener"),
            asyncio.create_task(self._matcher_loop(), name="matching-keeper-matcher"),
            asyncio.create_task(self._discovery_loop(), name="matching-keeper-discovery"),
            asyncio.create_task(self._prune_loop(), name="matching-keeper-prune"),
        ]

    async def stop(self) -> None:
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    async def _sleep_or_stop(self, seconds: float) -> None:
        if seconds <= 0:
            return
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            return

    def _is_trackable_market_account(self, market_account: MarketAccount) -> bool:
        if int(market_account.status) != int(MarketStatus.Open):
            return False
        if self.settings.REQUIRE_NOTARY_CONFIG and market_account.notary_config == Pubkey.default():
            return False
        return True

    async def _discover_market_targets(self) -> Dict[Pubkey, str]:
        targets: Dict[Pubkey, str] = {}

        if self.settings.MARKET_DISCOVERY_MODE == "explicit":
            configured = sorted(self.settings.tracked_markets, key=bytes)
            for market in configured:
                market_account = await asyncio.to_thread(self.client.fetch_market, market)
                if market_account and self._is_trackable_market_account(market_account):
                    targets[market] = "explicit"
            return targets

        discovered = await asyncio.to_thread(self.client.fetch_markets)
        filtered: List[Tuple[Pubkey, MarketAccount]] = [
            (pubkey, market_account)
            for pubkey, market_account in discovered
            if self._is_trackable_market_account(market_account)
        ]
        filtered.sort(key=lambda item: bytes(item[0]))
        for pubkey, _market_account in filtered[: self.settings.MAX_DISCOVERED_MARKETS]:
            targets[pubkey] = "program_scan"
        return targets

    async def _run_discovery_cycle(self) -> None:
        now = int(time.time())
        try:
            targets = await self._discover_market_targets()
            for market in list(self._market_sources):
                if market not in targets:
                    self._retire_market(
                        market,
                        market_status=self.engine.market_snapshot(market).get("market_status", DEFAULT_MARKET_STATUS),
                        discovery_source=self._market_sources.get(market, ""),
                        reason="market no longer discovered",
                    )

            for market, discovery_source in targets.items():
                if self._market_sources.get(market) != discovery_source:
                    logger.info("tracking market %s via %s", market, discovery_source)
                self._market_sources[market] = discovery_source
                await self.refresh_market_snapshot(market, discovery_source=discovery_source)

            self._last_discovery_at = now
            self._last_discovery_error = ""
        except Exception as exc:
            self._last_discovery_at = now
            self._last_discovery_error = str(exc)
            logger.exception("market discovery failed")

    async def _discovery_loop(self) -> None:
        while not self._stop_event.is_set():
            await self._sleep_or_stop(self.settings.DISCOVERY_INTERVAL_S)
            if self._stop_event.is_set():
                return
            await self._run_discovery_cycle()

    async def _run_prune_cycle(self) -> None:
        self._last_pruned_attempts = self.store.prune_old_attempts(self.settings.MATCH_ATTEMPT_RETENTION_DAYS)
        self._last_prune_at = int(time.time())

    async def _prune_loop(self) -> None:
        while not self._stop_event.is_set():
            await self._sleep_or_stop(self.settings.PRUNE_INTERVAL_S)
            if self._stop_event.is_set():
                return
            await self._run_prune_cycle()

    def _retire_market(
        self,
        market: Pubkey,
        *,
        market_status: str,
        discovery_source: str,
        reason: str,
    ) -> None:
        self._market_sources.pop(market, None)
        self.engine.retire_market(
            market,
            market_status=market_status,
            discovery_source=discovery_source,
            error=reason,
        )
        self.store.deactivate_market(
            market,
            market_status=market_status,
            discovery_source=discovery_source,
            reason=reason,
        )

    async def refresh_market_snapshot(self, market: Pubkey, *, discovery_source: Optional[str] = None) -> bool:
        discovery_source = discovery_source or self._market_sources.get(market, self.settings.MARKET_DISCOVERY_MODE)

        market_account = await asyncio.to_thread(self.client.fetch_market, market)
        if market_account is None:
            self._retire_market(
                market,
                market_status=DEFAULT_MARKET_STATUS,
                discovery_source=discovery_source,
                reason="market account not found",
            )
            return False

        market_status = _status_name(market_account.status)
        if not self._is_trackable_market_account(market_account):
            self._retire_market(
                market,
                market_status=market_status,
                discovery_source=discovery_source,
                reason="market is not open and trackable",
            )
            return False

        orders = await asyncio.to_thread(self.client.fetch_orders_for_market, market)
        now = int(time.time())
        self.engine.activate_market(market, discovery_source=discovery_source, seen_at=now)
        self.engine.set_market_metadata(
            market,
            quote_mint=market_account.quote_mint,
            market_status=market_status,
            discovery_source=discovery_source,
            seen_at=now,
        )
        self.engine.replace_orders(market, orders)
        self.store.replace_market_snapshot(
            market,
            market_account.quote_mint,
            market_status,
            discovery_source,
            orders,
            captured_at=now,
        )
        self._market_sources[market] = discovery_source
        return True

    async def _refresh_dirty_orders(self, market: Pubkey) -> None:
        dirty = self.engine.pop_dirty(market)
        if not dirty:
            return

        updates = await asyncio.to_thread(self.client.fetch_orders_bulk, dirty)
        now = int(time.time())
        self.engine.apply_order_updates(market, updates)
        self.store.apply_order_updates(market, updates, captured_at=now)

    def _parse_order_notification(self, message: object) -> Tuple[Optional[Pubkey], Optional[OrderAccount]]:
        order_pubkey, account_value = _notification_account_value(message)
        if order_pubkey is None:
            return None, None

        if account_value is None:
            return order_pubkey, None

        try:
            data_value = account_value.data if hasattr(account_value, "data") else account_value.get("data")
            raw = extract_account_bytes(data_value)
            if len(raw) < 8 or raw[:8] != ORDER_DISCRIMINATOR:
                return order_pubkey, None
            return order_pubkey, decode_order(raw)
        except Exception:
            return order_pubkey, None

    async def _listener_loop(self) -> None:
        filters = [DataSizeOpts(ORDER_ACCOUNT_SIZE)]

        while not self._stop_event.is_set():
            try:
                async with connect(self.settings.ws_url_effective) as websocket:
                    await websocket.program_subscribe(
                        self.client.program_id,
                        commitment=Confirmed,
                        encoding="base64",
                        filters=filters,
                    )
                    self._last_ws_connected_at = int(time.time())
                    self._last_ws_error = ""
                    logger.info("websocket listener connected to %s", self.settings.ws_url_effective)

                    async for message in websocket:
                        if self._stop_event.is_set():
                            return

                        self._last_ws_message_at = int(time.time())
                        order_pubkey, order = self._parse_order_notification(message)
                        if order_pubkey is None:
                            continue

                        if order is not None and order.market in self._market_sources:
                            self.engine.mark_dirty(order.market, order_pubkey)
                            continue

                        known_market = self.engine.find_market_for_order(order_pubkey)
                        if known_market is not None:
                            self.engine.mark_dirty(known_market, order_pubkey)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._last_ws_error = str(exc)
                logger.warning("websocket listener error: %s", exc)
                await self._sleep_or_stop(5)

    async def _matcher_loop(self) -> None:
        while not self._stop_event.is_set():
            matched_any = False
            active_markets = list(self._market_sources)

            for market in active_markets:
                if self._stop_event.is_set():
                    return

                try:
                    snapshot = self.engine.market_snapshot(market)
                    if not snapshot["active"]:
                        continue

                    if snapshot["last_snapshot_at"] <= 0 or int(time.time()) - int(snapshot["last_snapshot_at"]) >= self.settings.SNAPSHOT_RESYNC_S:
                        refreshed = await self.refresh_market_snapshot(market)
                        if not refreshed:
                            continue
                    else:
                        await self._refresh_dirty_orders(market)

                    for _ in range(self.settings.MAX_MATCHES_PER_MARKET):
                        snapshot = self.engine.market_snapshot(market)
                        quote_mint_str = snapshot["quote_mint"]
                        if not quote_mint_str:
                            refreshed = await self.refresh_market_snapshot(market)
                            if not refreshed:
                                break
                            snapshot = self.engine.market_snapshot(market)
                            quote_mint_str = snapshot["quote_mint"]
                        if not quote_mint_str:
                            raise ValueError(f"market {market} is missing quote mint metadata")

                        candidate = self.engine.best_crossed_match(market, self.settings.MAX_QTY_ATOMS)
                        if candidate is None:
                            break

                        try:
                            signature = await asyncio.to_thread(
                                self.client.match_orders,
                                market,
                                candidate.order_yes_pubkey,
                                candidate.order_no_pubkey,
                                candidate.order_yes.owner,
                                candidate.order_no.owner,
                                Pubkey.from_string(quote_mint_str),
                                candidate.qty_atoms,
                                self.settings.COMPUTE_UNIT_LIMIT,
                                self.settings.COMPUTE_UNIT_PRICE_MICRO_LAMPORTS,
                            )
                            self.engine.note_match_result(market, signature=signature)
                            self.store.record_match_attempt(
                                market=market,
                                order_yes=candidate.order_yes_pubkey,
                                order_no=candidate.order_no_pubkey,
                                qty_atoms=candidate.qty_atoms,
                                success=True,
                                signature=signature,
                            )
                            self.engine.mark_dirty(market, candidate.order_yes_pubkey)
                            self.engine.mark_dirty(market, candidate.order_no_pubkey)
                            await self._refresh_dirty_orders(market)
                            matched_any = True
                        except Exception as exc:
                            error_text = str(exc)
                            self.engine.note_match_result(market, error=error_text)
                            self.store.record_match_attempt(
                                market=market,
                                order_yes=candidate.order_yes_pubkey,
                                order_no=candidate.order_no_pubkey,
                                qty_atoms=candidate.qty_atoms,
                                success=False,
                                error_text=error_text,
                            )
                            if any(token in error_text.lower() for token in ("nocross", "do not cross", "account does not exist")):
                                self.engine.mark_dirty(market, candidate.order_yes_pubkey)
                                self.engine.mark_dirty(market, candidate.order_no_pubkey)
                                await self._refresh_dirty_orders(market)
                            else:
                                await self._sleep_or_stop(1)
                            break
                except Exception as exc:
                    error_text = str(exc)
                    self.engine.note_sync_error(market, error_text)
                    self.store.set_market_error(market, error_text)
                    logger.warning("market sync/match cycle failed for %s: %s", market, exc)

            await self._sleep_or_stop(0.05 if matched_any else self.settings.POLL_MS / 1000.0)

    def health(self) -> dict:
        now = int(time.time())
        active_markets = len(self._market_sources)
        ws_activity_at = max(self._last_ws_message_at, self._last_ws_connected_at)
        ws_age = now - ws_activity_at if ws_activity_at else None
        discovery_age = now - self._last_discovery_at if self._last_discovery_at else None
        prune_age = now - self._last_prune_at if self._last_prune_at else None
        ws_stale = bool(active_markets and ws_age is not None and ws_age > self.settings.STALE_WS_THRESHOLD_S)

        return {
            "ok": self._running and not ws_stale and not self._last_discovery_error,
            "running": self._running,
            "rpc_url": self.settings.RPC_URL,
            "ws_url": self.settings.ws_url_effective,
            "discovery_mode": self.settings.MARKET_DISCOVERY_MODE,
            "active_markets": active_markets,
            "websocket_stale": ws_stale,
            "last_ws_connected_at": self._last_ws_connected_at,
            "last_ws_message_at": self._last_ws_message_at,
            "last_ws_message_age_s": ws_age,
            "last_ws_error": self._last_ws_error,
            "last_discovery_at": self._last_discovery_at,
            "last_discovery_age_s": discovery_age,
            "last_discovery_error": self._last_discovery_error,
            "last_prune_at": self._last_prune_at,
            "last_prune_age_s": prune_age,
            "last_pruned_attempts": self._last_pruned_attempts,
        }

    def market_statuses(self) -> List[dict]:
        merged = {row["market"]: dict(row) for row in self.store.list_market_statuses()}
        for snapshot in self.engine.all_market_snapshots():
            merged.setdefault(snapshot["market"], {})
            merged[snapshot["market"]].update(snapshot)
        return [merged[key] for key in sorted(merged)]

    def recent_attempts(self, limit: int = 50) -> List[dict]:
        return self.store.list_recent_match_attempts(limit=limit)

    def metrics_text(self) -> str:
        now = int(time.time())
        snapshots = self.engine.all_market_snapshots()
        attempts = self.store.summarize_attempts()
        active_markets = sum(1 for item in snapshots if item["active"])
        open_orders = sum(int(item["open_orders"]) for item in snapshots if item["active"])
        ws_activity_at = max(self._last_ws_message_at, self._last_ws_connected_at)
        ws_age = now - ws_activity_at if ws_activity_at else -1
        discovery_age = now - self._last_discovery_at if self._last_discovery_at else -1
        prune_age = now - self._last_prune_at if self._last_prune_at else -1
        websocket_stale = int(bool(active_markets and ws_age > self.settings.STALE_WS_THRESHOLD_S))

        lines = [
            "# HELP prophet_matching_keeper_up Process health status.",
            "# TYPE prophet_matching_keeper_up gauge",
            f"prophet_matching_keeper_up {1 if self._running else 0}",
            "# HELP prophet_matching_keeper_active_markets Currently active markets.",
            "# TYPE prophet_matching_keeper_active_markets gauge",
            f"prophet_matching_keeper_active_markets {active_markets}",
            "# HELP prophet_matching_keeper_open_orders Open orders across active markets.",
            "# TYPE prophet_matching_keeper_open_orders gauge",
            f"prophet_matching_keeper_open_orders {open_orders}",
            "# HELP prophet_matching_keeper_match_attempts_total Total match attempts retained in SQLite.",
            "# TYPE prophet_matching_keeper_match_attempts_total counter",
            f"prophet_matching_keeper_match_attempts_total {attempts['total']}",
            "# HELP prophet_matching_keeper_match_attempts_success_total Successful match attempts retained in SQLite.",
            "# TYPE prophet_matching_keeper_match_attempts_success_total counter",
            f"prophet_matching_keeper_match_attempts_success_total {attempts['success_total']}",
            "# HELP prophet_matching_keeper_match_attempts_failure_total Failed match attempts retained in SQLite.",
            "# TYPE prophet_matching_keeper_match_attempts_failure_total counter",
            f"prophet_matching_keeper_match_attempts_failure_total {attempts['failure_total']}",
            "# HELP prophet_matching_keeper_last_ws_message_age_seconds Age of the last websocket message.",
            "# TYPE prophet_matching_keeper_last_ws_message_age_seconds gauge",
            f"prophet_matching_keeper_last_ws_message_age_seconds {ws_age}",
            "# HELP prophet_matching_keeper_websocket_stale Whether websocket ingestion is stale.",
            "# TYPE prophet_matching_keeper_websocket_stale gauge",
            f"prophet_matching_keeper_websocket_stale {websocket_stale}",
            "# HELP prophet_matching_keeper_last_discovery_age_seconds Age of the last market discovery cycle.",
            "# TYPE prophet_matching_keeper_last_discovery_age_seconds gauge",
            f"prophet_matching_keeper_last_discovery_age_seconds {discovery_age}",
            "# HELP prophet_matching_keeper_last_prune_age_seconds Age of the last match-attempt prune cycle.",
            "# TYPE prophet_matching_keeper_last_prune_age_seconds gauge",
            f"prophet_matching_keeper_last_prune_age_seconds {prune_age}",
            "# HELP prophet_matching_keeper_last_pruned_attempts Attempts deleted in the last prune cycle.",
            "# TYPE prophet_matching_keeper_last_pruned_attempts gauge",
            f"prophet_matching_keeper_last_pruned_attempts {self._last_pruned_attempts}",
        ]
        return "\n".join(lines) + "\n"
