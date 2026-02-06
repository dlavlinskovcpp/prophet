#apps/oracle-attester/src/config.py
import os
import json
from typing import Optional
from pydantic_settings import BaseSettings
from solders.keypair import Keypair
from solders.pubkey import Pubkey


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


class Settings(BaseSettings):
    RPC_URL: str = os.getenv("RPC_URL", "http://localhost:8899")
    ORACLE_KEYPAIR_PATH: str = os.getenv("ORACLE_KEYPAIR_PATH", "./id.json")
    PROPHET_PROGRAM_ID: str = os.getenv("PROPHET_PROGRAM_ID", "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A")
    RELAYER_KEYPAIR_PATH: str = os.getenv("RELAYER_KEYPAIR_PATH", "")
    PROOF_STORE_DIR: str = os.getenv("PROOF_STORE_DIR", "./proof_store")
    RESOLVER_STORE_DIR: str = os.getenv("RESOLVER_STORE_DIR", "./resolver_store")

    APP_ENV: str = os.getenv("APP_ENV", "production")

    # zkTLS Settings
    ZKTLS_MODE: str = os.getenv("ZKTLS_MODE", "reclaim_http")
    REQUIRE_ZKTLS: bool = _env_bool("REQUIRE_ZKTLS", True)
    RECLAIM_VERIFY_URL: str = os.getenv("RECLAIM_VERIFY_URL", "")
    RECLAIM_API_KEY: str = os.getenv("RECLAIM_API_KEY", "")
    ZKTLS_HTTP_TIMEOUT_S: float = float(os.getenv("ZKTLS_HTTP_TIMEOUT_S", "10"))
    ALLOW_MOCK_ZKTLS: bool = _env_bool("ALLOW_MOCK_ZKTLS", False)

    # Proof Fetcher Settings
    PROOF_FETCH_MODE: str = os.getenv("PROOF_FETCH_MODE", "local")  # "local" or "http"
    PROOF_FETCH_URL: str = os.getenv("PROOF_FETCH_URL", "")
    PROOF_FETCH_API_KEY: str = os.getenv("PROOF_FETCH_API_KEY", "")

    def _load_keypair(self, path_or_str: str) -> Optional[Keypair]:
        val = path_or_str.strip()
        if not val:
            return None

        if os.path.exists(val):
            with open(val, 'r') as f:
                val = f.read().strip()

        kp = None
        if val.startswith("[") and val.endswith("]"):
            try:
                int_list = json.loads(val)
                kp = Keypair.from_bytes(bytes(int_list))
            except Exception:
                pass

        elif "," in val and not val.startswith("["):
            try:
                int_list = [int(x) for x in val.split(",")]
                kp = Keypair.from_bytes(bytes(int_list))
            except Exception:
                pass

        if kp is None:
            try:
                from solders.keypair import Keypair as SKeypair
                kp = SKeypair.from_base58_string(val)
            except Exception:
                pass

        return kp

    def validate_zktls_runtime(self) -> None:
        mode = (self.ZKTLS_MODE or "").strip().lower()
        env = (self.APP_ENV or "production").strip().lower()
        is_dev_env = env in {"dev", "development", "local", "test"}

        if mode == "mock":
            if not (is_dev_env and self.ALLOW_MOCK_ZKTLS):
                raise ValueError(
                    "ZKTLS_MODE=mock is disabled. Use a real verifier mode "
                    "or explicitly set APP_ENV=development and ALLOW_MOCK_ZKTLS=1."
                )
            return

        if mode != "reclaim_http":
            raise ValueError(
                f"Unsupported ZKTLS_MODE '{self.ZKTLS_MODE}'. Supported: reclaim_http"
            )

        if not self.REQUIRE_ZKTLS:
            raise ValueError(
                "REQUIRE_ZKTLS must be enabled for non-mock zkTLS operation."
            )

        if not self.RECLAIM_VERIFY_URL:
            raise ValueError(
                "RECLAIM_VERIFY_URL is required when ZKTLS_MODE=reclaim_http."
            )

    @property
    def oracle_keypair(self) -> Keypair:
        kp = self._load_keypair(self.ORACLE_KEYPAIR_PATH)
        if kp is None:
            raise ValueError(f"Failed to load Oracle Keypair from: {self.ORACLE_KEYPAIR_PATH}")
        return kp

    @property
    def relayer_keypair(self) -> Keypair:
        return self._load_keypair(self.RELAYER_KEYPAIR_PATH)

    @property
    def program_id(self) -> Pubkey:
        return Pubkey.from_string(self.PROPHET_PROGRAM_ID)

settings = Settings()
