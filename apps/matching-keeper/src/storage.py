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
                    market_status TEXT NOT NULL DEFAULT '',
                    discovery_source TEXT NOT NULL DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    last_seen_at INTEGER NOT NULL DEFAULT 0,
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
            self._ensure_column(conn, "markets", "market_status", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "markets", "discovery_source", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "markets", "active", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column(conn, "markets", "last_seen_at", "INTEGER NOT NULL DEFAULT 0")

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        cols = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column in cols:
            return
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def upsert_market_metadata(
        self,
        market: Pubkey,
        *,
        quote_mint: Optional[Pubkey],
        market_status: str,
        discovery_source: str,
        active: bool,
        last_error: str = "",
        captured_at: Optional[int] = None,
    ) -> None:
        ts = int(captured_at or time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO markets (
                    market, quote_mint, market_status, discovery_source, active, last_seen_at, last_snapshot_at, last_error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(market) DO UPDATE SET
                    quote_mint = CASE WHEN excluded.quote_mint = '' THEN markets.quote_mint ELSE excluded.quote_mint END,
                    market_status = excluded.market_status,
                    discovery_source = excluded.discovery_source,
                    active = excluded.active,
                    last_seen_at = excluded.last_seen_at,
                    last_snapshot_at = CASE
                        WHEN excluded.last_snapshot_at = 0 THEN markets.last_snapshot_at
                        ELSE excluded.last_snapshot_at
                    END,
                    last_error = excluded.last_error
                """,
                (
                    str(market),
                    str(quote_mint) if quote_mint else "",
                    market_status,
                    discovery_source,
                    1 if active else 0,
                    ts,
                    ts,
                    last_error,
                ),
            )

    def replace_market_snapshot(
        self,
        market: Pubkey,
        quote_mint: Optional[Pubkey],
        market_status: str,
        discovery_source: str,
        orders: List[tuple[Pubkey, OrderAccount]],
        captured_at: Optional[int] = None,
    ) -> None:
        ts = int(captured_at or time.time())
        market_str = str(market)
        quote_mint_str = str(quote_mint) if quote_mint else ""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO markets (
                    market, quote_mint, market_status, discovery_source, active, last_seen_at, last_snapshot_at, last_error
                )
                VALUES (?, ?, ?, ?, 1, ?, ?, '')
                ON CONFLICT(market) DO UPDATE SET
                    quote_mint = excluded.quote_mint,
                    market_status = excluded.market_status,
                    discovery_source = excluded.discovery_source,
                    active = 1,
                    last_seen_at = excluded.last_seen_at,
                    last_snapshot_at = excluded.last_snapshot_at,
                    last_error = ''
                """,
                (market_str, quote_mint_str, market_status, discovery_source, ts, ts),
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
                INSERT INTO markets (
                    market, quote_mint, market_status, discovery_source, active, last_seen_at, last_snapshot_at, last_error
                )
                VALUES (?, '', '', '', 1, ?, ?, '')
                ON CONFLICT(market) DO UPDATE SET
                    active = 1,
                    last_seen_at = excluded.last_seen_at,
                    last_snapshot_at = excluded.last_snapshot_at,
                    last_error = ''
                """,
                (market_str, ts, ts),
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
                INSERT INTO markets (
                    market, quote_mint, market_status, discovery_source, active, last_seen_at, last_snapshot_at, last_error
                )
                VALUES (?, '', '', '', 1, ?, ?, ?)
                ON CONFLICT(market) DO UPDATE SET
                    active = 1,
                    last_seen_at = excluded.last_seen_at,
                    last_snapshot_at = excluded.last_snapshot_at,
                    last_error = excluded.last_error
                """,
                (str(market), ts, ts, error),
            )

    def deactivate_market(
        self,
        market: Pubkey,
        *,
        market_status: str,
        discovery_source: str,
        reason: str = "",
        captured_at: Optional[int] = None,
    ) -> None:
        ts = int(captured_at or time.time())
        market_str = str(market)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO markets (
                    market, quote_mint, market_status, discovery_source, active, last_seen_at, last_snapshot_at, last_error
                )
                VALUES (?, '', ?, ?, 0, ?, ?, ?)
                ON CONFLICT(market) DO UPDATE SET
                    market_status = excluded.market_status,
                    discovery_source = excluded.discovery_source,
                    active = 0,
                    last_seen_at = excluded.last_seen_at,
                    last_error = excluded.last_error
                """,
                (market_str, market_status, discovery_source, ts, ts, reason),
            )
            conn.execute("DELETE FROM orders WHERE market = ?", (market_str,))

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
                    m.market_status,
                    m.discovery_source,
                    m.active,
                    m.last_seen_at,
                    m.last_snapshot_at,
                    m.last_error,
                    COUNT(o.order_pubkey) AS open_orders
                FROM markets m
                LEFT JOIN orders o ON o.market = m.market
                GROUP BY
                    m.market,
                    m.quote_mint,
                    m.market_status,
                    m.discovery_source,
                    m.active,
                    m.last_seen_at,
                    m.last_snapshot_at,
                    m.last_error
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

    def summarize_attempts(self) -> dict:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS success_total,
                    SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failure_total
                FROM match_attempts
                """
            ).fetchone()
        return {
            "total": int(row["total"] or 0),
            "success_total": int(row["success_total"] or 0),
            "failure_total": int(row["failure_total"] or 0),
        }

    def prune_old_attempts(self, retention_days: int) -> int:
        cutoff = int(time.time()) - int(retention_days) * 24 * 60 * 60
        with self._connect() as conn:
            before = conn.total_changes
            conn.execute("DELETE FROM match_attempts WHERE created_at < ?", (cutoff,))
            return conn.total_changes - before
