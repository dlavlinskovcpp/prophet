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


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw.strip())


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    return float(raw.strip())


class Settings(BaseSettings):
    RPC_URL: str = os.getenv("RPC_URL", "http://localhost:8899")
    ORACLE_KEYPAIR_PATH: str = os.getenv("ORACLE_KEYPAIR_PATH", "./id.json")
    PROPHET_PROGRAM_ID: str = os.getenv("PROPHET_PROGRAM_ID", "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A")
    RELAYER_KEYPAIR_PATH: str = os.getenv("RELAYER_KEYPAIR_PATH", "")
    PROOF_STORE_DIR: str = os.getenv("PROOF_STORE_DIR", "./proof_store")
    RESOLVER_STORE_DIR: str = os.getenv("RESOLVER_STORE_DIR", "./resolver_store")
    RESOLVER_REGISTRY_MODE: str = os.getenv("RESOLVER_REGISTRY_MODE", "directory")
    RESOLVER_REGISTRY_URL: str = os.getenv("RESOLVER_REGISTRY_URL", "")
    RESOLVER_REGISTRY_API_KEY: str = os.getenv("RESOLVER_REGISTRY_API_KEY", "")
    RESOLVER_REGISTRY_TIMEOUT_S: float = _env_float("RESOLVER_REGISTRY_TIMEOUT_S", 5.0)
    RESOLVER_REGISTRY_REQUIRE_TLS: bool = _env_bool("RESOLVER_REGISTRY_REQUIRE_TLS", True)
    RESOLVER_REGISTRY_CACHE_TTL_S: float = _env_float("RESOLVER_REGISTRY_CACHE_TTL_S", 300.0)
    RESOLVER_REGISTRY_CACHE_MAX_ENTRIES: int = _env_int("RESOLVER_REGISTRY_CACHE_MAX_ENTRIES", 1024)
    RESOLVER_REGISTRY_ALLOW_STALE_ON_ERROR: bool = _env_bool("RESOLVER_REGISTRY_ALLOW_STALE_ON_ERROR", True)
    RESOLVER_REGISTRY_REQUIRE_AUTH: bool = _env_bool("RESOLVER_REGISTRY_REQUIRE_AUTH", True)
    RESOLVER_REGISTRY_SERVICE_API_KEY: str = os.getenv("RESOLVER_REGISTRY_SERVICE_API_KEY", "")
    RESOLVER_REGISTRY_MAX_REQUEST_BYTES: int = _env_int("RESOLVER_REGISTRY_MAX_REQUEST_BYTES", 100_000)
    RESOLVER_REGISTRY_AUDIT_LOG_PATH: str = os.getenv(
        "RESOLVER_REGISTRY_AUDIT_LOG_PATH",
        "./audit/resolver-registry.jsonl",
    )
    ATTESTER_AUDIT_LOG_PATH: str = os.getenv("ATTESTER_AUDIT_LOG_PATH", "./audit/attester.jsonl")
    REMOTE_SIGNER_AUDIT_LOG_PATH: str = os.getenv("REMOTE_SIGNER_AUDIT_LOG_PATH", "./audit/remote-signer.jsonl")

    APP_ENV: str = os.getenv("APP_ENV", "production")

    # zkTLS Settings
    ZKTLS_MODE: str = os.getenv("ZKTLS_MODE", "reclaim_http")
    REQUIRE_ZKTLS: bool = _env_bool("REQUIRE_ZKTLS", True)
    RECLAIM_VERIFY_URL: str = os.getenv("RECLAIM_VERIFY_URL", "")
    RECLAIM_API_KEY: str = os.getenv("RECLAIM_API_KEY", "")
    ZKTLS_HTTP_TIMEOUT_S: float = float(os.getenv("ZKTLS_HTTP_TIMEOUT_S", "10"))

    # Proof Fetcher Settings
    PROOF_FETCH_MODE: str = os.getenv("PROOF_FETCH_MODE", "local")  # "local" or "http"
    PROOF_FETCH_URL: str = os.getenv("PROOF_FETCH_URL", "")
    PROOF_FETCH_API_KEY: str = os.getenv("PROOF_FETCH_API_KEY", "")

    # Notary signer mode
    NOTARY_SIGNER_MODE: str = os.getenv("NOTARY_SIGNER_MODE", "remote")  # "remote" or "local"
    ALLOW_LOCAL_NOTARY_KEYS: bool = _env_bool("ALLOW_LOCAL_NOTARY_KEYS", False)
    NOTARY_KEYPAIR_PATHS: str = os.getenv("NOTARY_KEYPAIR_PATHS", "")
    REMOTE_SIGNER_URL: str = os.getenv("REMOTE_SIGNER_URL", "")
    REMOTE_SIGNER_API_KEY: str = os.getenv("REMOTE_SIGNER_API_KEY", "")
    REMOTE_SIGNER_TIMEOUT_S: float = _env_float("REMOTE_SIGNER_TIMEOUT_S", 5.0)
    REMOTE_SIGNER_REQUIRE_TLS: bool = _env_bool("REMOTE_SIGNER_REQUIRE_TLS", True)
    REMOTE_SIGNER_REQUIRE_AUTH: bool = _env_bool("REMOTE_SIGNER_REQUIRE_AUTH", True)
    REMOTE_SIGNER_REQUIRE_ALLOWLIST: bool = _env_bool("REMOTE_SIGNER_REQUIRE_ALLOWLIST", False)
    REMOTE_SIGNER_ALLOWLIST_MODE: str = os.getenv("REMOTE_SIGNER_ALLOWLIST_MODE", "env")
    REMOTE_SIGNER_ALLOWED_PUBKEYS: str = os.getenv("REMOTE_SIGNER_ALLOWED_PUBKEYS", "")
    REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH: str = os.getenv("REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH", "")
    REMOTE_SIGNER_ALLOWLIST_REFRESH_S: float = _env_float("REMOTE_SIGNER_ALLOWLIST_REFRESH_S", 30.0)
    REMOTE_SIGNER_MAX_MESSAGE_BYTES: int = _env_int("REMOTE_SIGNER_MAX_MESSAGE_BYTES", 10_000)
    REMOTE_SIGNER_BACKEND: str = os.getenv("REMOTE_SIGNER_BACKEND", "local_keypairs")
    REMOTE_SIGNER_COMMAND: str = os.getenv("REMOTE_SIGNER_COMMAND", "")
    REMOTE_SIGNER_COMMAND_TIMEOUT_S: float = _env_float("REMOTE_SIGNER_COMMAND_TIMEOUT_S", 5.0)

    # API hardening
    REQUIRE_API_AUTH: bool = _env_bool("REQUIRE_API_AUTH", True)
    API_AUTH_TOKEN: str = os.getenv("API_AUTH_TOKEN", "")
    RATE_LIMIT_ENABLED: bool = _env_bool("RATE_LIMIT_ENABLED", True)
    RATE_LIMIT_MAX_REQUESTS: int = _env_int("RATE_LIMIT_MAX_REQUESTS", 30)
    RATE_LIMIT_WINDOW_S: int = _env_int("RATE_LIMIT_WINDOW_S", 60)
    RATE_LIMIT_TRUST_X_FORWARDED_FOR: bool = _env_bool("RATE_LIMIT_TRUST_X_FORWARDED_FOR", False)
    MAX_REQUEST_BYTES: int = _env_int("MAX_REQUEST_BYTES", 1_000_000)
    METRICS_ENABLED: bool = _env_bool("METRICS_ENABLED", True)

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

    def validate_signer_runtime(self) -> None:
        mode = (self.NOTARY_SIGNER_MODE or "").strip().lower()
        env = (self.APP_ENV or "production").strip().lower()
        is_dev_env = env in {"dev", "development", "local", "test"}

        if mode not in {"local", "remote"}:
            raise ValueError(
                f"Unsupported NOTARY_SIGNER_MODE '{self.NOTARY_SIGNER_MODE}'. Supported: remote, local."
            )

        if mode == "local" and not (is_dev_env or self.ALLOW_LOCAL_NOTARY_KEYS):
            raise ValueError(
                "Local notary keys are disabled for production. "
                "Use NOTARY_SIGNER_MODE=remote or explicitly set ALLOW_LOCAL_NOTARY_KEYS=1."
            )

        if mode == "remote":
            if not self.REMOTE_SIGNER_URL:
                raise ValueError("REMOTE_SIGNER_URL is required when NOTARY_SIGNER_MODE=remote.")
            if self.REMOTE_SIGNER_TIMEOUT_S <= 0:
                raise ValueError("REMOTE_SIGNER_TIMEOUT_S must be > 0.")
            if (
                self.REMOTE_SIGNER_REQUIRE_TLS
                and not self.REMOTE_SIGNER_URL.startswith("https://")
                and not self.REMOTE_SIGNER_URL.startswith("http://127.0.0.1")
                and not self.REMOTE_SIGNER_URL.startswith("http://localhost")
            ):
                raise ValueError(
                    "REMOTE_SIGNER_URL must use https when REMOTE_SIGNER_REQUIRE_TLS=1 "
                    "(localhost/127.0.0.1 exempted)."
                )

    def validate_resolver_registry_runtime(self) -> None:
        mode = (self.RESOLVER_REGISTRY_MODE or "").strip().lower()

        if self.RESOLVER_REGISTRY_CACHE_TTL_S <= 0:
            raise ValueError("RESOLVER_REGISTRY_CACHE_TTL_S must be > 0.")
        if self.RESOLVER_REGISTRY_CACHE_MAX_ENTRIES <= 0:
            raise ValueError("RESOLVER_REGISTRY_CACHE_MAX_ENTRIES must be > 0.")

        if mode not in {"directory", "http"}:
            raise ValueError(
                f"Unsupported RESOLVER_REGISTRY_MODE '{self.RESOLVER_REGISTRY_MODE}'. "
                "Supported: directory, http."
            )

        if mode == "directory":
            if not (self.RESOLVER_STORE_DIR or "").strip():
                raise ValueError(
                    "RESOLVER_STORE_DIR is required when RESOLVER_REGISTRY_MODE=directory."
                )
            return

        if not self.RESOLVER_REGISTRY_URL:
            raise ValueError(
                "RESOLVER_REGISTRY_URL is required when RESOLVER_REGISTRY_MODE=http."
            )
        if self.RESOLVER_REGISTRY_TIMEOUT_S <= 0:
            raise ValueError("RESOLVER_REGISTRY_TIMEOUT_S must be > 0.")
        if (
            self.RESOLVER_REGISTRY_REQUIRE_TLS
            and not self.RESOLVER_REGISTRY_URL.startswith("https://")
            and not self.RESOLVER_REGISTRY_URL.startswith("http://127.0.0.1")
            and not self.RESOLVER_REGISTRY_URL.startswith("http://localhost")
        ):
            raise ValueError(
                "RESOLVER_REGISTRY_URL must use https when RESOLVER_REGISTRY_REQUIRE_TLS=1 "
                "(localhost/127.0.0.1 exempted)."
            )

    def validate_remote_signer_service_runtime(self) -> None:
        backend = (self.REMOTE_SIGNER_BACKEND or "").strip().lower()
        allowlist_mode = (self.REMOTE_SIGNER_ALLOWLIST_MODE or "").strip().lower()
        env = (self.APP_ENV or "production").strip().lower()
        is_dev_env = env in {"dev", "development", "local", "test"}

        if backend not in {"local_keypairs", "command"}:
            raise ValueError(
                f"Unsupported REMOTE_SIGNER_BACKEND '{self.REMOTE_SIGNER_BACKEND}'. "
                "Supported: local_keypairs, command."
            )

        if backend == "local_keypairs" and not (is_dev_env or self.ALLOW_LOCAL_NOTARY_KEYS):
            raise ValueError(
                "REMOTE_SIGNER_BACKEND=local_keypairs is disabled for production. "
                "Use REMOTE_SIGNER_BACKEND=command or explicitly set ALLOW_LOCAL_NOTARY_KEYS=1."
            )

        if backend == "command":
            if not self.REMOTE_SIGNER_COMMAND.strip():
                raise ValueError(
                    "REMOTE_SIGNER_COMMAND is required when REMOTE_SIGNER_BACKEND=command."
                )
            if self.REMOTE_SIGNER_COMMAND_TIMEOUT_S <= 0:
                raise ValueError("REMOTE_SIGNER_COMMAND_TIMEOUT_S must be > 0.")

        if allowlist_mode not in {"env", "file"}:
            raise ValueError(
                f"Unsupported REMOTE_SIGNER_ALLOWLIST_MODE '{self.REMOTE_SIGNER_ALLOWLIST_MODE}'. "
                "Supported: env, file."
            )
        if self.REMOTE_SIGNER_ALLOWLIST_REFRESH_S <= 0:
            raise ValueError("REMOTE_SIGNER_ALLOWLIST_REFRESH_S must be > 0.")

        require_allowlist = bool(self.REMOTE_SIGNER_REQUIRE_ALLOWLIST)
        if backend == "command" and not is_dev_env:
            require_allowlist = True

        if not require_allowlist:
            return

        if allowlist_mode == "env" and not self.REMOTE_SIGNER_ALLOWED_PUBKEYS.strip():
            raise ValueError(
                "REMOTE_SIGNER_ALLOWED_PUBKEYS must be configured when a signer allowlist is required."
            )
        if allowlist_mode == "file" and not self.REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH.strip():
            raise ValueError(
                "REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH must be configured when REMOTE_SIGNER_ALLOWLIST_MODE=file."
            )

    def validate_resolver_registry_service_runtime(self) -> None:
        if not (self.RESOLVER_STORE_DIR or "").strip():
            raise ValueError("RESOLVER_STORE_DIR is required for the resolver registry service.")
        if self.RESOLVER_REGISTRY_REQUIRE_AUTH and not self.RESOLVER_REGISTRY_SERVICE_API_KEY:
            raise ValueError(
                "RESOLVER_REGISTRY_SERVICE_API_KEY is required when RESOLVER_REGISTRY_REQUIRE_AUTH=1."
            )
        if self.RESOLVER_REGISTRY_MAX_REQUEST_BYTES <= 0:
            raise ValueError("RESOLVER_REGISTRY_MAX_REQUEST_BYTES must be > 0.")

    def validate_api_runtime(self) -> None:
        if self.REQUIRE_API_AUTH and not self.API_AUTH_TOKEN:
            raise ValueError("API_AUTH_TOKEN is required when REQUIRE_API_AUTH=1.")
        if self.RATE_LIMIT_MAX_REQUESTS <= 0:
            raise ValueError("RATE_LIMIT_MAX_REQUESTS must be > 0.")
        if self.RATE_LIMIT_WINDOW_S <= 0:
            raise ValueError("RATE_LIMIT_WINDOW_S must be > 0.")
        if self.MAX_REQUEST_BYTES <= 0:
            raise ValueError("MAX_REQUEST_BYTES must be > 0.")

    def validate_runtime(self) -> None:
        self.validate_zktls_runtime()
        self.validate_signer_runtime()
        self.validate_resolver_registry_runtime()
        self.validate_api_runtime()

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
