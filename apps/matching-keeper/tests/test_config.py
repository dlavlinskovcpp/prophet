import os

import pytest
from pydantic import ValidationError

from src.config import Settings


PUBLIC_DEVNET_PROGRAM_ID = "3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE"
OTHER_VALID_PROGRAM_ID = "11111111111111111111111111111111"


def test_program_id_missing_is_rejected(monkeypatch):
    monkeypatch.delenv("PROPHET_PROGRAM_ID", raising=False)
    with pytest.raises(ValidationError, match="PROPHET_PROGRAM_ID"):
        Settings()


def test_program_id_empty_is_rejected():
    with pytest.raises(ValidationError, match="PROPHET_PROGRAM_ID is required"):
        Settings(PROPHET_PROGRAM_ID="")


def test_program_id_malformed_base58_is_rejected():
    with pytest.raises(ValidationError, match="valid Solana pubkey"):
        Settings(PROPHET_PROGRAM_ID="not-a-valid-0OIl-pubkey")


def test_program_id_invalid_pubkey_length_is_rejected():
    with pytest.raises(ValidationError, match="valid Solana pubkey"):
        Settings(PROPHET_PROGRAM_ID="1111")


def test_current_public_devnet_program_id_is_accepted():
    settings = Settings(PROPHET_PROGRAM_ID=PUBLIC_DEVNET_PROGRAM_ID)
    assert settings.PROPHET_PROGRAM_ID == PUBLIC_DEVNET_PROGRAM_ID


def test_environment_is_read_when_settings_are_constructed(monkeypatch):
    monkeypatch.setenv("RPC_URL", "https://rpc.example")
    settings = Settings(PROPHET_PROGRAM_ID=PUBLIC_DEVNET_PROGRAM_ID)
    assert settings.RPC_URL == "https://rpc.example"


def test_dotenv_is_read_without_mutating_process_environment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("RPC_URL", raising=False)
    (tmp_path / ".env").write_text("RPC_URL=https://dotenv.example\n", encoding="utf-8")

    settings = Settings(PROPHET_PROGRAM_ID=PUBLIC_DEVNET_PROGRAM_ID)

    assert settings.RPC_URL == "https://dotenv.example"
    assert os.environ.get("RPC_URL") is None


def test_empty_optional_compute_settings_remain_unset(monkeypatch):
    monkeypatch.setenv("COMPUTE_UNIT_LIMIT", "")
    monkeypatch.setenv("COMPUTE_UNIT_PRICE_MICRO_LAMPORTS", "")
    settings = Settings(PROPHET_PROGRAM_ID=PUBLIC_DEVNET_PROGRAM_ID)
    assert settings.COMPUTE_UNIT_LIMIT is None
    assert settings.COMPUTE_UNIT_PRICE_MICRO_LAMPORTS is None


def test_another_valid_program_id_is_technically_accepted():
    settings = Settings(PROPHET_PROGRAM_ID=OTHER_VALID_PROGRAM_ID)
    assert settings.PROPHET_PROGRAM_ID == OTHER_VALID_PROGRAM_ID


def test_production_keeper_requires_operated_resolver_allowlist():
    settings = Settings(
        PROPHET_PROGRAM_ID=PUBLIC_DEVNET_PROGRAM_ID,
        ENVIRONMENT="public-devnet",
        RPC_URL="https://rpc.example",
        WS_URL="wss://rpc.example",
        PAYER_KEYPAIR_PATH="/run/secrets/keeper-id.json",
        DB_PATH="/var/lib/prophet/matcher.db",
        MARKET_DISCOVERY_MODE="program_scan",
        REQUIRE_OPERATED_RESOLVER_SUPPORT=True,
        OPERATED_SUPPORTED_RESOLVER_HASHES="",
    )
    with pytest.raises(ValueError, match="OPERATED_SUPPORTED_RESOLVER_HASHES"):
        settings.validate_runtime()


def test_production_keeper_rejects_plaintext_and_unbounded_compute_price():
    settings = Settings(
        PROPHET_PROGRAM_ID=PUBLIC_DEVNET_PROGRAM_ID,
        ENVIRONMENT="public-devnet",
        RPC_URL="http://rpc.example",
        WS_URL="ws://rpc.example",
        PAYER_KEYPAIR_PATH="/run/secrets/keeper-id.json",
        DB_PATH="/var/lib/prophet/matcher.db",
        MARKET_DISCOVERY_MODE="program_scan",
        REQUIRE_OPERATED_RESOLVER_SUPPORT=True,
        OPERATED_SUPPORTED_RESOLVER_HASHES="aa" * 32,
        COMPUTE_UNIT_PRICE_MICRO_LAMPORTS=1_000_001,
    )
    with pytest.raises(ValueError, match="https"):
        settings.validate_runtime()


def test_production_keeper_rejects_unbounded_compute_price_after_transport_checks():
    settings = Settings(
        PROPHET_PROGRAM_ID=PUBLIC_DEVNET_PROGRAM_ID,
        ENVIRONMENT="public-devnet",
        RPC_URL="https://rpc.example",
        WS_URL="wss://rpc.example",
        PAYER_KEYPAIR_PATH="/run/secrets/keeper-id.json",
        DB_PATH="/var/lib/prophet/matcher.db",
        MARKET_DISCOVERY_MODE="program_scan",
        REQUIRE_OPERATED_RESOLVER_SUPPORT=True,
        OPERATED_SUPPORTED_RESOLVER_HASHES="aa" * 32,
        COMPUTE_UNIT_PRICE_MICRO_LAMPORTS=1_000_001,
    )
    with pytest.raises(ValueError, match="COMPUTE_UNIT_PRICE"):
        settings.validate_runtime()
