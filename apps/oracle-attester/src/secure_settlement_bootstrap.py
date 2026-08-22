"""Trusted construction of the only production settlement-authorizing service."""
from __future__ import annotations

import os
from pathlib import Path

from .agreed_settlement_signer import AgreedSettlementSigner
from .resolution_coordinator_store import ResolutionCoordinatorStore, VerifierBinding
from .secure_settlement_runtime import (
    load_secure_auth_tokens,
    load_secure_settlement_runtime,
)
from .secure_settlement_service import (
    SecureSettlementEngine,
    create_secure_settlement_service,
)
from .settlement_simulation import SettlementSimulationService
from .settlement_submission import SettlementSubmissionService
from .settlement_transaction_builder import SettlementTransactionBuilder
from .runtime_clock import wall_clock_ms
from .signing_journal import SigningJournal
from .vault_transit_signer_identity import VaultTransitSignerClient
from .vault_transit_threshold_signer import ThresholdResolutionSigner


def _runtime_path() -> Path:
    path = os.getenv("PROPHET_SETTLEMENT_RUNTIME_CONFIG", "")
    if not path:
        raise ValueError("secure settlement runtime configuration path is required")
    return Path(path)


def _descriptor(config):
    return {
        "schema": "prophet.adapter-descriptor.v2",
        "schema_version": "2.0.0",
        "adapter_id": config.expected_verifier_id,
        "adapter_version": config.expected_verifier_version,
        "implementation_digest": config.expected_verifier_implementation_digest,
    }


def build_secure_settlement_service():
    resources = []
    try:
        secure = load_secure_settlement_runtime(
            _runtime_path(),
            enable_mainnet=os.getenv("PROPHET_ENABLE_MAINNET_SETTLEMENT", "") == "1",
        )
        runtime = secure.runtime
        if runtime.coordinator is None or runtime.signing is None:
            raise ValueError("secure settlement dependencies missing")
        api_token, token_a, token_b = load_secure_auth_tokens(secure)
        state = ResolutionCoordinatorStore(
            runtime.coordinator.sqlite_path,
            verifier_a=VerifierBinding("A", _descriptor(runtime.coordinator.verifier_a)),
            verifier_b=VerifierBinding("B", _descriptor(runtime.coordinator.verifier_b)),
            clock_ms=wall_clock_ms,
        )
        resources.append(state)
        journal = SigningJournal(runtime.signing.journal_path)
        resources.append(journal)
        signer_a = VaultTransitSignerClient(
            signing=runtime.signing,
            signer=runtime.signing.signer_a,
            config_fingerprint=runtime.fingerprint(),
            vault_token=token_a,
        )
        signer_b = VaultTransitSignerClient(
            signing=runtime.signing,
            signer=runtime.signing.signer_b,
            config_fingerprint=runtime.fingerprint(),
            vault_token=token_b,
        )
        resources.extend((signer_a, signer_b))
        threshold = ThresholdResolutionSigner(
            signer_a=signer_a, signer_b=signer_b, journal=journal
        )
        agreed = AgreedSettlementSigner(
            coordinator_state=state,
            signing_journal=journal,
            threshold_signer=threshold,
            clock_ms=wall_clock_ms,
        )
        builder = SettlementTransactionBuilder(
            coordinator_state=state,
            signing_journal=journal,
            threshold_signer=threshold,
            solana_runtime=runtime.solana,
            clock_ms=wall_clock_ms,
        )
        simulation = SettlementSimulationService.from_runtime_config(
            builder=builder, runtime_config=runtime
        )
        submission = SettlementSubmissionService.from_runtime_config(
            runtime_config=runtime,
            simulation_service=simulation,
            signing_journal=journal,
        )
        engine = SecureSettlementEngine(
            agreed_signer=agreed, submission_service=submission
        )
        return create_secure_settlement_service(
            engine=engine,
            auth_token=api_token,
            close_resources=resources,
        )
    except Exception:
        for resource in reversed(resources):
            close = getattr(resource, "close", None)
            if close is not None:
                close()
        return create_secure_settlement_service(startup_error="startup_invalid")
