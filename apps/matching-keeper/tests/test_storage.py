import sqlite3

import pytest
from solders.pubkey import Pubkey

from prophet_sdk import OrderSide
from prophet_sdk.types import OrderAccount

from src.storage import U64_MAX, SQLiteStateStore, decode_u64


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
        fee_remaining_atoms=0,
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


@pytest.mark.parametrize("value", [0, 2**63 - 1, 2**63, U64_MAX])
def test_protocol_u64_values_are_lossless_decimal_text(tmp_path, value):
    store = SQLiteStateStore(str(tmp_path / "boundary.db"))
    store.init()
    market = _pk(1)
    order_pubkey = _pk(10)
    boundary_order = _order(
        market_seed=1,
        owner_seed=2,
        side=OrderSide.BuyYes,
        seq=value,
        price=65_000_000,
        qty=value,
    )
    boundary_order.created_ts = 1_700_000_000

    store.replace_market_snapshot(
        market,
        _pk(9),
        "Open",
        "explicit",
        [
            (
                order_pubkey,
                boundary_order,
            )
        ],
        captured_at=1_700_000_100,
    )
    store.record_match_attempt(
        market=market,
        order_yes=order_pubkey,
        order_no=_pk(11),
        qty_atoms=value,
        success=True,
    )

    with store._connect() as conn:
        order = conn.execute(
            "SELECT seq, qty_remaining_atoms, escrow_remaining_atoms, typeof(seq) AS seq_type "
            "FROM orders WHERE order_pubkey = ?",
            (str(order_pubkey),),
        ).fetchone()
        attempt = conn.execute("SELECT qty_atoms, typeof(qty_atoms) AS qty_type FROM match_attempts").fetchone()
    if value == 0:
        assert order is None
    else:
        assert order["seq"] == str(value)
        assert order["qty_remaining_atoms"] == str(value)
        assert order["escrow_remaining_atoms"] == str(value)
        assert order["seq_type"] == "text"
    assert attempt["qty_atoms"] == str(value)
    assert attempt["qty_type"] == "text"
    assert store.list_recent_match_attempts()[0]["qty_atoms"] == value
    assert decode_u64(str(value)) == value


def test_existing_integer_schema_migrates_without_loss(tmp_path):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE orders (
                order_pubkey TEXT PRIMARY KEY,
                market TEXT NOT NULL,
                owner TEXT NOT NULL,
                side INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                limit_p_yes_e8 INTEGER NOT NULL,
                qty_remaining_atoms INTEGER NOT NULL,
                escrow_remaining_atoms INTEGER NOT NULL,
                created_ts INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE match_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                market TEXT NOT NULL,
                order_yes TEXT NOT NULL,
                order_no TEXT NOT NULL,
                qty_atoms INTEGER NOT NULL,
                success INTEGER NOT NULL,
                signature TEXT NOT NULL DEFAULT '',
                error_text TEXT NOT NULL DEFAULT ''
            );
            """
        )
        conn.execute(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(_pk(10)), str(_pk(1)), str(_pk(2)), 0, 2**63 - 1, 1, 2**63 - 1, 2**63 - 1, 1, 1),
        )
        conn.execute(
            "INSERT INTO match_attempts (created_at, market, order_yes, order_no, qty_atoms, success) VALUES (?, ?, ?, ?, ?, ?)",
            (1, str(_pk(1)), str(_pk(10)), str(_pk(11)), 2**63 - 1, 1),
        )

    SQLiteStateStore(str(db_path)).init()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT typeof(seq), seq FROM orders").fetchone() == ("text", str(2**63 - 1))
        assert conn.execute("SELECT typeof(qty_atoms), qty_atoms FROM match_attempts").fetchone() == (
            "text",
            str(2**63 - 1),
        )


def test_malformed_negative_legacy_u64_is_rejected(tmp_path):
    db_path = tmp_path / "malformed.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE orders (order_pubkey TEXT PRIMARY KEY, market TEXT, owner TEXT, side INTEGER, "
            "seq INTEGER, limit_p_yes_e8 INTEGER, qty_remaining_atoms INTEGER, escrow_remaining_atoms INTEGER, "
            "created_ts INTEGER, updated_at INTEGER)"
        )
        conn.execute(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(_pk(10)), str(_pk(1)), str(_pk(2)), 0, -1, 1, 1, 1, 1, 1),
        )

    with pytest.raises(ValueError, match="protocol u64"):
        SQLiteStateStore(str(db_path)).init()
