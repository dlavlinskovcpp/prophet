import pytest
from solders.pubkey import Pubkey

from src.attester import AttesterService
from src.config import settings


def _service() -> AttesterService:
    return object.__new__(AttesterService)


def test_threshold_markets_are_allowed(monkeypatch):
    del monkeypatch
    svc = _service()

    svc._enforce_resolution_mode_policy({"notary_config": Pubkey.new_unique()})


def test_legacy_single_oracle_is_rejected(monkeypatch):
    del monkeypatch
    svc = _service()

    with pytest.raises(PermissionError):
        svc._enforce_resolution_mode_policy({"notary_config": Pubkey.default()})
