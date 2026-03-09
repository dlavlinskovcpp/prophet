import os
from pathlib import Path
from typing import List, Optional

from pydantic_settings import BaseSettings
from solders.pubkey import Pubkey


def _derive_ws_url(rpc_url: str) -> str:
    if rpc_url.startswith("https://"):
        return "wss://" + rpc_url[len("https://") :]
    if rpc_url.startswith("http://"):
        return "ws://" + rpc_url[len("http://") :]
    return rpc_url


class Settings(BaseSettings):
    RPC_URL: str = os.getenv("RPC_URL", "http://127.0.0.1:8899")
    WS_URL: str = os.getenv("WS_URL", "")
    PROPHET_PROGRAM_ID: str = os.getenv("PROPHET_PROGRAM_ID", "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A")
    PAYER_KEYPAIR_PATH: str = os.getenv("PAYER_KEYPAIR_PATH", "./id.json")
    MARKET_DISCOVERY_MODE: str = os.getenv("MARKET_DISCOVERY_MODE", "explicit")
    MARKETS: str = os.getenv("MARKETS", "")
    DISCOVERY_INTERVAL_S: int = int(os.getenv("DISCOVERY_INTERVAL_S", "60"))
    MAX_DISCOVERED_MARKETS: int = int(os.getenv("MAX_DISCOVERED_MARKETS", "500"))
    REQUIRE_NOTARY_CONFIG: bool = os.getenv("REQUIRE_NOTARY_CONFIG", "1").strip().lower() in {"1", "true", "yes", "on"}
    DB_PATH: str = os.getenv("DB_PATH", "./state/matcher.db")
    POLL_MS: int = int(os.getenv("POLL_MS", "250"))
    SNAPSHOT_RESYNC_S: int = int(os.getenv("SNAPSHOT_RESYNC_S", "300"))
    MATCH_ATTEMPT_RETENTION_DAYS: int = int(os.getenv("MATCH_ATTEMPT_RETENTION_DAYS", "30"))
    PRUNE_INTERVAL_S: int = int(os.getenv("PRUNE_INTERVAL_S", "3600"))
    STALE_WS_THRESHOLD_S: int = int(os.getenv("STALE_WS_THRESHOLD_S", "120"))
    MAX_QTY_ATOMS: int = int(os.getenv("MAX_QTY_ATOMS", "1000000"))
    MAX_MATCHES_PER_MARKET: int = int(os.getenv("MAX_MATCHES_PER_MARKET", "10"))
    COMPUTE_UNIT_LIMIT: Optional[int] = int(os.getenv("COMPUTE_UNIT_LIMIT", "")) if os.getenv("COMPUTE_UNIT_LIMIT", "").strip() else None
    COMPUTE_UNIT_PRICE_MICRO_LAMPORTS: Optional[int] = (
        int(os.getenv("COMPUTE_UNIT_PRICE_MICRO_LAMPORTS", ""))
        if os.getenv("COMPUTE_UNIT_PRICE_MICRO_LAMPORTS", "").strip()
        else None
    )
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def tracked_markets(self) -> List[Pubkey]:
        raw = [item.strip() for item in self.MARKETS.split(",") if item.strip()]
        uniq = []
        seen = set()
        for item in raw:
            if item in seen:
                continue
            seen.add(item)
            uniq.append(Pubkey.from_string(item))
        return uniq

    @property
    def ws_url_effective(self) -> str:
        return self.WS_URL.strip() or _derive_ws_url(self.RPC_URL)

    def validate_runtime(self) -> None:
        if self.MARKET_DISCOVERY_MODE not in {"explicit", "program_scan"}:
            raise ValueError("MARKET_DISCOVERY_MODE must be one of: explicit, program_scan.")
        if self.MARKET_DISCOVERY_MODE == "explicit" and not self.tracked_markets:
            raise ValueError("MARKETS must contain at least one tracked market pubkey when MARKET_DISCOVERY_MODE=explicit.")
        if self.DISCOVERY_INTERVAL_S <= 0:
            raise ValueError("DISCOVERY_INTERVAL_S must be positive.")
        if self.MAX_DISCOVERED_MARKETS <= 0:
            raise ValueError("MAX_DISCOVERED_MARKETS must be positive.")
        if self.POLL_MS <= 0:
            raise ValueError("POLL_MS must be positive.")
        if self.SNAPSHOT_RESYNC_S <= 0:
            raise ValueError("SNAPSHOT_RESYNC_S must be positive.")
        if self.MATCH_ATTEMPT_RETENTION_DAYS <= 0:
            raise ValueError("MATCH_ATTEMPT_RETENTION_DAYS must be positive.")
        if self.PRUNE_INTERVAL_S <= 0:
            raise ValueError("PRUNE_INTERVAL_S must be positive.")
        if self.STALE_WS_THRESHOLD_S <= 0:
            raise ValueError("STALE_WS_THRESHOLD_S must be positive.")
        if self.MAX_QTY_ATOMS <= 0:
            raise ValueError("MAX_QTY_ATOMS must be positive.")
        if self.MAX_MATCHES_PER_MARKET <= 0:
            raise ValueError("MAX_MATCHES_PER_MARKET must be positive.")

    def ensure_runtime_dirs(self) -> None:
        Path(self.DB_PATH).parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
