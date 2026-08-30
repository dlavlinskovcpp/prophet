"""Retired compatibility entry point for the former dual-token service.

It intentionally creates only an unready HTTP tombstone.  The historical
bootstrap loaded both Vault credentials and performed quorum signing locally;
that capability is prohibited pending independent signer-process integration.
"""
from __future__ import annotations

class LegacySecureSettlementRetired(RuntimeError):
    """The historical in-process 2-of-2 settlement service is retired."""


def build_secure_settlement_service():
    """Fail before any legacy runtime or credential acquisition can occur."""
    raise LegacySecureSettlementRetired("legacy_secure_settlement_retired")
