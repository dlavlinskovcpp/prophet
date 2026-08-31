import ipaddress
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from solders.pubkey import Pubkey


MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS = 1_000_000
_PRODUCTION_ENVIRONMENTS = frozenset(("public-devnet", "mainnet"))


def _derive_ws_url(rpc_url: str) -> str:
    if rpc_url.startswith("https://"):
        return "wss://" + rpc_url[len("https://") :]
    if rpc_url.startswith("http://"):
        return "ws://" + rpc_url[len("http://") :]
    return rpc_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ENVIRONMENT: str = "localtest"
    RPC_URL: str = "http://127.0.0.1:8899"
    WS_URL: str = ""
    PROPHET_PROGRAM_ID: str
    PAYER_KEYPAIR_PATH: str = "./id.json"
    MARKET_DISCOVERY_MODE: str = "explicit"
    MARKETS: str = ""
    DISCOVERY_INTERVAL_S: int = 60
    MAX_DISCOVERED_MARKETS: int = 500
    REQUIRE_NOTARY_CONFIG: bool = True
    DB_PATH: str = "./state/matcher.db"
    POLL_MS: int = 250
    SNAPSHOT_RESYNC_S: int = 300
    MATCH_ATTEMPT_RETENTION_DAYS: int = 30
    PRUNE_INTERVAL_S: int = 3600
    STALE_WS_THRESHOLD_S: int = 120
    MAX_QTY_ATOMS: int = 1_000_000
    MAX_MATCHES_PER_MARKET: int = 10
    COMPUTE_UNIT_LIMIT: Optional[int] = None
    COMPUTE_UNIT_PRICE_MICRO_LAMPORTS: Optional[int] = None
    OPS_HOST: str = "127.0.0.1"
    OPS_PORT: int = 8010
    OPS_PROTECTED_INGRESS: bool = False
    OPS_API_AUTH_TOKEN: str = ""
    OPS_EXPOSE_MARKETS: bool = False
    OPS_EXPOSE_ATTEMPTS: bool = False
    OPS_EXPOSE_METRICS: bool = False
    MATCHING_FAILURE_MAX_AGE_S: int = 60
    REQUIRE_OPERATED_RESOLVER_SUPPORT: bool = False
    OPERATED_SUPPORTED_RESOLVER_HASHES: str = ""
    LOG_LEVEL: str = "INFO"

    @field_validator("COMPUTE_UNIT_LIMIT", "COMPUTE_UNIT_PRICE_MICRO_LAMPORTS", mode="before")
    @classmethod
    def _empty_optional_int_as_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("PROPHET_PROGRAM_ID")
    @classmethod
    def _validate_program_id(cls, value: str) -> str:
        program_id = str(value or "").strip()
        if not program_id:
            raise ValueError("PROPHET_PROGRAM_ID is required.")
        try:
            parsed = Pubkey.from_string(program_id)
        except Exception as exc:
            raise ValueError("PROPHET_PROGRAM_ID must be a valid Solana pubkey.") from exc
        if str(parsed) != program_id:
            raise ValueError("PROPHET_PROGRAM_ID must be canonical base58.")
        return program_id

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

    @property
    def operated_supported_resolver_hashes(self) -> frozenset[str]:
        values = frozenset(item.strip().lower() for item in self.OPERATED_SUPPORTED_RESOLVER_HASHES.split(",") if item.strip())
        invalid = [item for item in values if len(item) != 64 or any(char not in "0123456789abcdef" for char in item)]
        if invalid:
            raise ValueError("OPERATED_SUPPORTED_RESOLVER_HASHES must contain lowercase 32-byte hex hashes.")
        return values

    def validate_runtime(self) -> None:
        environment = self.ENVIRONMENT.strip().lower()
        if environment not in {"localtest", "public-devnet", "mainnet"}:
            raise ValueError("ENVIRONMENT must be localtest, public-devnet, or mainnet.")
        if not self.RPC_URL.strip() or not self.ws_url_effective.strip():
            raise ValueError("RPC_URL and WS_URL must be configured.")
        parsed_rpc = urlsplit(self.RPC_URL)
        parsed_ws = urlsplit(self.ws_url_effective)
        if any(value is None for value in (parsed_rpc.hostname, parsed_ws.hostname)):
            raise ValueError("RPC_URL and WS_URL must include a host.")
        if any(value is not None for value in (parsed_rpc.username, parsed_rpc.password, parsed_ws.username, parsed_ws.password)):
            raise ValueError("RPC_URL and WS_URL must not embed credentials.")
        if environment in _PRODUCTION_ENVIRONMENTS and (parsed_rpc.query or parsed_ws.query or parsed_rpc.fragment or parsed_ws.fragment):
            raise ValueError("production RPC_URL and WS_URL must not embed credentials in query or fragment components.")
        if environment in _PRODUCTION_ENVIRONMENTS:
            if parsed_rpc.scheme != "https":
                raise ValueError("production keeper RPC_URL must use https.")
            if parsed_ws.scheme != "wss":
                raise ValueError("production keeper WS_URL must use wss.")
            for label, value in (("PAYER_KEYPAIR_PATH", self.PAYER_KEYPAIR_PATH), ("DB_PATH", self.DB_PATH)):
                if not Path(value).is_absolute():
                    raise ValueError(f"production {label} must be absolute.")
        else:
            local_rpc = parsed_rpc.hostname in {"127.0.0.1", "localhost", "::1"}
            local_ws = parsed_ws.hostname in {"127.0.0.1", "localhost", "::1"}
            if parsed_rpc.scheme not in {"http", "https"} or parsed_ws.scheme not in {"ws", "wss"}:
                raise ValueError("localtest RPC/WS URLs must use http(s)/ws(s).")
            if parsed_rpc.scheme == "http" and not local_rpc:
                raise ValueError("plaintext RPC is permitted only for loopback localtest.")
            if parsed_ws.scheme == "ws" and not local_ws:
                raise ValueError("plaintext websocket is permitted only for loopback localtest.")
        try:
            host = ipaddress.ip_address(self.OPS_HOST)
        except ValueError:
            if self.OPS_HOST not in {"localhost"}:
                raise ValueError("OPS_HOST must be a literal IP or localhost.") from None
            host = None
        loopback = host.is_loopback if host is not None else True
        if not 1 <= self.OPS_PORT <= 65535:
            raise ValueError("OPS_PORT must be between 1 and 65535.")
        if not loopback and environment in _PRODUCTION_ENVIRONMENTS and not self.OPS_PROTECTED_INGRESS:
            raise ValueError("non-loopback production ops bind requires OPS_PROTECTED_INGRESS=1.")
        if self.OPS_PROTECTED_INGRESS and len(self.OPS_API_AUTH_TOKEN) < 16:
            raise ValueError("OPS_API_AUTH_TOKEN must be at least 16 characters in protected-ingress mode.")
        if self.COMPUTE_UNIT_PRICE_MICRO_LAMPORTS is not None and (
            self.COMPUTE_UNIT_PRICE_MICRO_LAMPORTS < 0
            or self.COMPUTE_UNIT_PRICE_MICRO_LAMPORTS > MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS
        ):
            raise ValueError(
                f"COMPUTE_UNIT_PRICE_MICRO_LAMPORTS must be between 0 and {MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS}."
            )
        if self.MATCHING_FAILURE_MAX_AGE_S <= 0:
            raise ValueError("MATCHING_FAILURE_MAX_AGE_S must be positive.")
        supported_hashes = self.operated_supported_resolver_hashes
        if environment in _PRODUCTION_ENVIRONMENTS and not self.REQUIRE_OPERATED_RESOLVER_SUPPORT:
            raise ValueError("production keeper must require operated resolver support.")
        if self.REQUIRE_OPERATED_RESOLVER_SUPPORT and not supported_hashes:
            raise ValueError("OPERATED_SUPPORTED_RESOLVER_HASHES is required when operated resolver support is enforced.")
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
