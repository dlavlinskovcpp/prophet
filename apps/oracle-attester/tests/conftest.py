"""Shared deterministic clock wiring for historical Resolver V2 fixtures."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _deterministic_authorization_clock(monkeypatch):
    """Keep legacy fixture timestamps deterministic without changing production defaults."""
    clock = lambda: 100
    from src import agreed_settlement_signer, resolution_coordinator_store, settlement_transaction_builder

    monkeypatch.setattr(resolution_coordinator_store, "wall_clock_ms", clock)
    monkeypatch.setattr(agreed_settlement_signer, "wall_clock_ms", clock)
    monkeypatch.setattr(settlement_transaction_builder, "wall_clock_ms", clock)
