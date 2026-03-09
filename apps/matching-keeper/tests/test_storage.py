from solders.pubkey import Pubkey

from prophet_sdk import OrderSide
from prophet_sdk.types import OrderAccount

from src.storage import SQLiteStateStore


def _pk(seed: int) -> Pubkey:
    return Pubkey.from_bytes(bytes([seed]) * 32)


def _order(*, market_seed: int, owner_seed: int, side: OrderSide, seq: int, price: int, qty: int) -> OrderAccount:
    return OrderAccount(
        market=_pk(market_seed),
        owner=_pk(owner_seed),
        side=side,
        seq=seq,
        limit_p_yes_e8=price,
        qty_remaining_atoms=qty,
        escrow_remaining_atoms=qty,
        created_ts=1_700_000_000 + seq,
    )


def test_replace_snapshot_and_updates_and_attempts(tmp_path):
    db_path = tmp_path / "matcher.db"
    store = SQLiteStateStore(str(db_path))
    store.init()

    market = _pk(1)
    quote_mint = _pk(9)
    order_yes = _pk(10)
    order_no = _pk(11)

    store.replace_market_snapshot(
        market,
        quote_mint,
        "Open",
        "explicit",
        [
            (order_yes, _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=65_000_000, qty=20)),
            (order_no, _order(market_seed=1, owner_seed=3, side=OrderSide.BuyNo, seq=2, price=60_000_000, qty=15)),
        ],
        captured_at=1_700_000_100,
    )

    statuses = store.list_market_statuses()
    assert statuses[0]["market"] == str(market)
    assert statuses[0]["quote_mint"] == str(quote_mint)
    assert statuses[0]["market_status"] == "Open"
    assert statuses[0]["discovery_source"] == "explicit"
    assert statuses[0]["active"] == 1
    assert statuses[0]["open_orders"] == 2

    store.apply_order_updates(
        market,
        {
            order_yes: _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=65_000_000, qty=5),
            order_no: None,
        },
        captured_at=1_700_000_120,
    )

    statuses = store.list_market_statuses()
    assert statuses[0]["open_orders"] == 1
    assert statuses[0]["last_snapshot_at"] == 1_700_000_120

    store.record_match_attempt(
        market=market,
        order_yes=order_yes,
        order_no=order_no,
        qty_atoms=5,
        success=True,
        signature="sig-123",
    )
    attempts = store.list_recent_match_attempts(limit=5)
    assert len(attempts) == 1
    assert attempts[0]["market"] == str(market)
    assert attempts[0]["success"] == 1
    assert attempts[0]["signature"] == "sig-123"

    summary = store.summarize_attempts()
    assert summary == {"total": 1, "success_total": 1, "failure_total": 0}

    store.deactivate_market(
        market,
        market_status="Resolved",
        discovery_source="program_scan",
        reason="market no longer discovered",
        captured_at=1_700_000_150,
    )
    statuses = store.list_market_statuses()
    assert statuses[0]["active"] == 0
    assert statuses[0]["market_status"] == "Resolved"
    assert statuses[0]["discovery_source"] == "program_scan"
    assert statuses[0]["open_orders"] == 0
    assert statuses[0]["last_error"] == "market no longer discovered"


def test_prune_old_attempts(tmp_path):
    db_path = tmp_path / "matcher.db"
    store = SQLiteStateStore(str(db_path))
    store.init()

    market = _pk(1)
    order_yes = _pk(10)
    order_no = _pk(11)

    store.record_match_attempt(
        market=market,
        order_yes=order_yes,
        order_no=order_no,
        qty_atoms=5,
        success=True,
        signature="fresh",
    )
    store.record_match_attempt(
        market=market,
        order_yes=order_yes,
        order_no=order_no,
        qty_atoms=5,
        success=False,
        error_text="stale",
    )

    with store._connect() as conn:
        conn.execute("UPDATE match_attempts SET created_at = ? WHERE signature = ''", (1,))

    deleted = store.prune_old_attempts(retention_days=30)
    assert deleted == 1

    attempts = store.list_recent_match_attempts(limit=10)
    assert len(attempts) == 1
    assert attempts[0]["signature"] == "fresh"
