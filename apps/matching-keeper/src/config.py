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
    MARKETS: str = os.getenv("MARKETS", "")
    DB_PATH: str = os.getenv("DB_PATH", "./state/matcher.db")
    POLL_MS: int = int(os.getenv("POLL_MS", "250"))
    SNAPSHOT_RESYNC_S: int = int(os.getenv("SNAPSHOT_RESYNC_S", "300"))
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
        if not self.tracked_markets:
            raise ValueError("MARKETS must contain at least one tracked market pubkey.")
        if self.POLL_MS <= 0:
            raise ValueError("POLL_MS must be positive.")
        if self.SNAPSHOT_RESYNC_S <= 0:
            raise ValueError("SNAPSHOT_RESYNC_S must be positive.")
        if self.MAX_QTY_ATOMS <= 0:
            raise ValueError("MAX_QTY_ATOMS must be positive.")
        if self.MAX_MATCHES_PER_MARKET <= 0:
            raise ValueError("MAX_MATCHES_PER_MARKET must be positive.")

    def ensure_runtime_dirs(self) -> None:
        Path(self.DB_PATH).parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
