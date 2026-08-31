from __future__ import annotations

import sqlite3
import time
from typing import Dict, List, Optional

from solders.pubkey import Pubkey

from prophet_sdk.types import OrderAccount


U64_MAX = (1 << 64) - 1
_ORDER_U64_COLUMNS = (
    "seq",
    "qty_remaining_atoms",
    "escrow_remaining_atoms",
)
_MATCH_U64_COLUMNS = ("qty_atoms",)


def encode_u64(value: int) -> str:
    """Encode a Solana u64 as canonical unsigned decimal text for SQLite."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= U64_MAX:
        raise ValueError("protocol u64 value out of range")
    return str(value)


def decode_u64(value: object) -> int:
    """Decode a canonical decimal u64 without accepting negative/malformed data."""
    if isinstance(value, bool):
        raise ValueError("protocol u64 value is malformed")
    if isinstance(value, int):
        decoded = value
    elif isinstance(value, str) and value and value.isascii() and value.isdecimal():
        if len(value) > 1 and value.startswith("0"):
            raise ValueError("protocol u64 value is not canonical decimal")
        decoded = int(value)
    else:
        raise ValueError("protocol u64 value is malformed")
    if not 0 <= decoded <= U64_MAX:
        raise ValueError("protocol u64 value out of range")
    return decoded


class SQLiteStateStore:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        journal_mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA foreign_keys = ON")
        effective = (
            str(journal_mode).lower(),
            int(conn.execute("PRAGMA synchronous").fetchone()[0]),
            int(conn.execute("PRAGMA busy_timeout").fetchone()[0]),
            int(conn.execute("PRAGMA foreign_keys").fetchone()[0]),
        )
        if effective != ("wal", 2, 5000, 1):
            conn.close()
            raise RuntimeError(f"sqlite_durability_contract_mismatch:{effective!r}")
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
                    seq TEXT NOT NULL,
                    limit_p_yes_e8 INTEGER NOT NULL,
                    qty_remaining_atoms TEXT NOT NULL,
                    escrow_remaining_atoms TEXT NOT NULL,
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
                    qty_atoms TEXT NOT NULL,
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
            self._migrate_u64_columns(conn, "orders", _ORDER_U64_COLUMNS)
            self._migrate_u64_columns(conn, "match_attempts", _MATCH_U64_COLUMNS)

    @staticmethod
    def _table_info(conn: sqlite3.Connection, table: str) -> Dict[str, str]:
        return {
            row["name"]: str(row["type"]).upper()
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }

    def _migrate_u64_columns(
        self,
        conn: sqlite3.Connection,
        table: str,
        u64_columns: tuple[str, ...],
    ) -> None:
        info = self._table_info(conn, table)
        if not info:
            return
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        for row in rows:
            for column in u64_columns:
                decode_u64(row[column])

        if all(info[column] == "TEXT" for column in u64_columns):
            return

        if table == "orders":
            conn.execute("DROP INDEX IF EXISTS idx_orders_market")
            conn.execute("ALTER TABLE orders RENAME TO orders_legacy_u64")
            conn.execute(
                """
                CREATE TABLE orders (
                    order_pubkey TEXT PRIMARY KEY,
                    market TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    side INTEGER NOT NULL,
                    seq TEXT NOT NULL,
                    limit_p_yes_e8 INTEGER NOT NULL,
                    qty_remaining_atoms TEXT NOT NULL,
                    escrow_remaining_atoms TEXT NOT NULL,
                    created_ts INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            conn.executemany(
                """
                INSERT INTO orders (
                    order_pubkey, market, owner, side, seq, limit_p_yes_e8,
                    qty_remaining_atoms, escrow_remaining_atoms, created_ts, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        row["order_pubkey"], row["market"], row["owner"], row["side"],
                        encode_u64(decode_u64(row["seq"])), row["limit_p_yes_e8"],
                        encode_u64(decode_u64(row["qty_remaining_atoms"])),
                        encode_u64(decode_u64(row["escrow_remaining_atoms"])),
                        row["created_ts"], row["updated_at"],
                    )
                    for row in rows
                ],
            )
            conn.execute("DROP TABLE orders_legacy_u64")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_market ON orders(market)")
            return

        if table == "match_attempts":
            conn.execute("DROP INDEX IF EXISTS idx_match_attempts_market_id")
            conn.execute("ALTER TABLE match_attempts RENAME TO match_attempts_legacy_u64")
            conn.execute(
                """
                CREATE TABLE match_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    market TEXT NOT NULL,
                    order_yes TEXT NOT NULL,
                    order_no TEXT NOT NULL,
                    qty_atoms TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    signature TEXT NOT NULL DEFAULT '',
                    error_text TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.executemany(
                """
                INSERT INTO match_attempts (
                    id, created_at, market, order_yes, order_no, qty_atoms,
                    success, signature, error_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        row["id"], row["created_at"], row["market"], row["order_yes"],
                        row["order_no"], encode_u64(decode_u64(row["qty_atoms"])),
                        row["success"], row["signature"], row["error_text"],
                    )
                    for row in rows
                ],
            )
            conn.execute("DROP TABLE match_attempts_legacy_u64")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_match_attempts_market_id "
                "ON match_attempts(market, id DESC)"
            )
            return

        raise ValueError(f"unsupported u64 migration table: {table}")

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
                        encode_u64(order.seq),
                        int(order.limit_p_yes_e8),
                        encode_u64(order.qty_remaining_atoms),
                        encode_u64(order.escrow_remaining_atoms),
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
                        encode_u64(order.seq),
                        int(order.limit_p_yes_e8),
                        encode_u64(order.qty_remaining_atoms),
                        encode_u64(order.escrow_remaining_atoms),
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
                    encode_u64(qty_atoms),
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
        result = []
        for row in rows:
            item = dict(row)
            for column in _MATCH_U64_COLUMNS:
                item[column] = decode_u64(item[column])
            result.append(item)
        return result

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
