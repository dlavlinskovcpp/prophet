import asyncio
import time

from solders.pubkey import Pubkey

from prophet_sdk.types import MarketAccount, MarketOutcome, MarketStatus

from src.service import MatchingKeeperService
from src.config import Settings


def _pk(seed: int) -> Pubkey:
    return Pubkey.from_bytes(bytes([seed]) * 32)


def _market_account(*, status: MarketStatus, notary_config: Pubkey) -> MarketAccount:
    return MarketAccount(
        authority=_pk(1),
        oracle_authority=_pk(2),
        quote_mint=_pk(3),
        quote_vault=_pk(4),
        fee_recipient=_pk(5),
        notary_config=notary_config,
        resolver_hash=bytes([9]) * 32,
        proof_hash=bytes(32),
        public_inputs_hash=bytes(32),
        open_ts=1_700_000_000,
        lock_ts=1_700_000_100,
        resolve_ts=1_700_000_200,
        resolved_ts=0,
        min_order_qty_atoms=1,
        min_escrow_atoms=1,
        accrued_protocol_fees_atoms=0,
        next_order_seq=0,
        open_orders_total=0,
        max_open_orders_total=128,
        max_open_orders_per_user=16,
        protocol_fee_bps=0,
        quote_decimals=6,
        status=status,
        outcome=MarketOutcome.Undecided,
        bump=255,
    )


class FakeClient:
    def __init__(self, markets):
        self.markets = markets

    def fetch_markets(self):
        return self.markets

    def fetch_market(self, pubkey: Pubkey):
        for market_pubkey, market_account in self.markets:
            if market_pubkey == pubkey:
                return market_account
        return None


def test_program_scan_discovery_filters_non_open_and_legacy_markets(tmp_path):
    open_v2_market = _pk(10)
    open_legacy_market = _pk(11)
    resolved_v2_market = _pk(12)

    client = FakeClient(
        [
            (open_v2_market, _market_account(status=MarketStatus.Open, notary_config=_pk(50))),
            (open_legacy_market, _market_account(status=MarketStatus.Open, notary_config=Pubkey.default())),
            (resolved_v2_market, _market_account(status=MarketStatus.Resolved, notary_config=_pk(51))),
        ]
    )
    settings = Settings(
        DB_PATH=str(tmp_path / "matcher.db"),
        MARKET_DISCOVERY_MODE="program_scan",
        MARKETS="",
        REQUIRE_NOTARY_CONFIG=True,
    )
    service = MatchingKeeperService(settings, client=client)

    targets = asyncio.run(service._discover_market_targets())

    assert targets == {open_v2_market: "program_scan"}


def test_health_reports_stale_websocket_for_active_markets(tmp_path):
    settings = Settings(
        DB_PATH=str(tmp_path / "matcher.db"),
        MARKET_DISCOVERY_MODE="explicit",
        MARKETS=str(_pk(10)),
        STALE_WS_THRESHOLD_S=5,
    )
    service = MatchingKeeperService(settings, client=FakeClient([]))
    market = _pk(10)

    service._running = True
    service._market_sources[market] = "explicit"
    service.engine.activate_market(market, discovery_source="explicit", seen_at=int(time.time()) - 10)
    service._last_ws_connected_at = int(time.time()) - 30
    service._last_discovery_at = int(time.time()) - 1

    health = service.health()

    assert health["websocket_stale"] is True
    assert health["ok"] is False
