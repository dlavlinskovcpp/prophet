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


def test_another_valid_program_id_is_technically_accepted():
    settings = Settings(PROPHET_PROGRAM_ID=OTHER_VALID_PROGRAM_ID)
    assert settings.PROPHET_PROGRAM_ID == OTHER_VALID_PROGRAM_ID
