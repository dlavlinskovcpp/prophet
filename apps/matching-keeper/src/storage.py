from __future__ import annotations

import sqlite3
import time
from typing import Dict, List, Optional

from solders.pubkey import Pubkey

from prophet_sdk.types import OrderAccount


class SQLiteStateStore:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS markets (
                    market TEXT PRIMARY KEY,
                    quote_mint TEXT NOT NULL DEFAULT '',
                    last_snapshot_at INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS orders (
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
                CREATE INDEX IF NOT EXISTS idx_orders_market ON orders(market);

                CREATE TABLE IF NOT EXISTS match_attempts (
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
                CREATE INDEX IF NOT EXISTS idx_match_attempts_market_id ON match_attempts(market, id DESC);
                """
            )

    def replace_market_snapshot(
        self,
        market: Pubkey,
        quote_mint: Optional[Pubkey],
        orders: List[tuple[Pubkey, OrderAccount]],
        captured_at: Optional[int] = None,
    ) -> None:
        ts = int(captured_at or time.time())
        market_str = str(market)
        quote_mint_str = str(quote_mint) if quote_mint else ""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO markets (market, quote_mint, last_snapshot_at, last_error)
                VALUES (?, ?, ?, '')
                ON CONFLICT(market) DO UPDATE SET
                    quote_mint = excluded.quote_mint,
                    last_snapshot_at = excluded.last_snapshot_at,
                    last_error = ''
                """,
                (market_str, quote_mint_str, ts),
            )
            conn.execute("DELETE FROM orders WHERE market = ?", (market_str,))
            conn.executemany(
                """
                INSERT INTO orders (
                    order_pubkey, market, owner, side, seq, limit_p_yes_e8,
                    qty_remaining_atoms, escrow_remaining_atoms, created_ts, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        str(order_pubkey),
                        market_str,
                        str(order.owner),
                        int(order.side),
                        int(order.seq),
                        int(order.limit_p_yes_e8),
                        int(order.qty_remaining_atoms),
                        int(order.escrow_remaining_atoms),
                        int(order.created_ts),
                        ts,
                    )
                    for order_pubkey, order in orders
                    if order.qty_remaining_atoms > 0
                ],
            )

    def apply_order_updates(
        self,
        market: Pubkey,
        updates: Dict[Pubkey, Optional[OrderAccount]],
        captured_at: Optional[int] = None,
    ) -> None:
        ts = int(captured_at or time.time())
        market_str = str(market)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO markets (market, quote_mint, last_snapshot_at, last_error)
                VALUES (?, '', ?, '')
                ON CONFLICT(market) DO UPDATE SET
                    last_snapshot_at = excluded.last_snapshot_at,
                    last_error = ''
                """,
                (market_str, ts),
            )
            for order_pubkey, order in updates.items():
                if order is None or order.qty_remaining_atoms <= 0:
                    conn.execute("DELETE FROM orders WHERE order_pubkey = ?", (str(order_pubkey),))
                    continue
                conn.execute(
                    """
                    INSERT INTO orders (
                        order_pubkey, market, owner, side, seq, limit_p_yes_e8,
                        qty_remaining_atoms, escrow_remaining_atoms, created_ts, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(order_pubkey) DO UPDATE SET
                        market = excluded.market,
                        owner = excluded.owner,
                        side = excluded.side,
                        seq = excluded.seq,
                        limit_p_yes_e8 = excluded.limit_p_yes_e8,
                        qty_remaining_atoms = excluded.qty_remaining_atoms,
                        escrow_remaining_atoms = excluded.escrow_remaining_atoms,
                        created_ts = excluded.created_ts,
                        updated_at = excluded.updated_at
                    """,
                    (
                        str(order_pubkey),
                        market_str,
                        str(order.owner),
                        int(order.side),
                        int(order.seq),
                        int(order.limit_p_yes_e8),
                        int(order.qty_remaining_atoms),
                        int(order.escrow_remaining_atoms),
                        int(order.created_ts),
                        ts,
                    ),
                )

    def set_market_error(self, market: Pubkey, error: str, captured_at: Optional[int] = None) -> None:
        ts = int(captured_at or time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO markets (market, quote_mint, last_snapshot_at, last_error)
                VALUES (?, '', ?, ?)
                ON CONFLICT(market) DO UPDATE SET
                    last_snapshot_at = excluded.last_snapshot_at,
                    last_error = excluded.last_error
                """,
                (str(market), ts, error),
            )

    def record_match_attempt(
        self,
        *,
        market: Pubkey,
        order_yes: Pubkey,
        order_no: Pubkey,
        qty_atoms: int,
        success: bool,
        signature: str = "",
        error_text: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO match_attempts (
                    created_at, market, order_yes, order_no, qty_atoms, success, signature, error_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(time.time()),
                    str(market),
                    str(order_yes),
                    str(order_no),
                    int(qty_atoms),
                    1 if success else 0,
                    signature,
                    error_text,
                ),
            )

    def list_market_statuses(self) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    m.market,
                    m.quote_mint,
                    m.last_snapshot_at,
                    m.last_error,
                    COUNT(o.order_pubkey) AS open_orders
                FROM markets m
                LEFT JOIN orders o ON o.market = m.market
                GROUP BY m.market, m.quote_mint, m.last_snapshot_at, m.last_error
                ORDER BY m.market
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def list_recent_match_attempts(self, limit: int = 50) -> List[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    created_at,
                    market,
                    order_yes,
                    order_no,
                    qty_atoms,
                    success,
                    signature,
                    error_text
                FROM match_attempts
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        return [dict(row) for row in rows]
