"""Trusted startup construction for the standalone coordinator HTTP service."""
from __future__ import annotations

import os
from pathlib import Path

from .coordinator_service import create_coordinator_service
from .external_threshold_validator import ExternalThresholdBundleValidator
from .production_external_signers import ExternalFixedRoleSignerPair, ExternalSignerBinding
from .production_settlement_executor import ProductionSettlementExecutor
from .resolution_coordinator import ResolutionCoordinator
from .resolution_coordinator_store import ResolutionCoordinatorStore, VerifierBinding
from .runtime_config import load_runtime_config
from .settlement_simulation import SettlementSimulationService
from .settlement_submission import SettlementSubmissionService
from .settlement_transaction_builder import SettlementTransactionBuilder
from .signing_journal import SigningJournal
from .verifier_service_client import VerifierServiceClient


def _runtime_path() -> Path:
    path = os.getenv("PROPHET_COORDINATOR_RUNTIME_CONFIG", "")
    if not path:
        raise ValueError("coordinator runtime configuration path is required")
    return Path(path)


def _descriptor(config):
    return {
        "schema": "prophet.adapter-descriptor.v2",
        "schema_version": "2.0.0",
        "adapter_id": config.expected_verifier_id,
        "adapter_version": config.expected_verifier_version,
        "implementation_digest": config.expected_verifier_implementation_digest,
    }


def build_coordinator_service():
    resources = []
    try:
        runtime_path = _runtime_path()
        config = load_runtime_config(runtime_path)
        # Production coordinator startup is bound directly to the current
        # external fixed-role topology.  The retired dual-token runtime is not
        # consulted and cannot be a fallback or a source of credentials.
        require_settlement_context = config.mode == "production"
        if require_settlement_context and config.settlement_execution is None:
            raise ValueError("production coordinator settlement execution configuration is required")
        if require_settlement_context and config.external_signers is None:
            raise ValueError("production coordinator external signer configuration is required")
        if require_settlement_context and config.signing is not None:
            raise ValueError("production coordinator Vault signer credentials are forbidden")
        if config.coordinator is None:
            raise ValueError("coordinator configuration is required")
        token = os.getenv(config.coordinator.internal_auth.token_env, "")
        if not token:
            raise ValueError("coordinator internal token is required")
        state = ResolutionCoordinatorStore(
            config.coordinator.sqlite_path,
            verifier_a=VerifierBinding("A", _descriptor(config.coordinator.verifier_a)),
            verifier_b=VerifierBinding("B", _descriptor(config.coordinator.verifier_b)),
        )
        resources.append(state)
        client_a = VerifierServiceClient.from_runtime(config, slot="A")
        client_b = VerifierServiceClient.from_runtime(config, slot="B")
        resources.extend((client_a, client_b))
        coordinator = ResolutionCoordinator(state=state, verifier_client_a=client_a, verifier_client_b=client_b)
        executor = None
        if require_settlement_context:
            external = config.external_signers
            binding_a = ExternalSignerBinding("A", external.signer_a.endpoint, external.signer_a.signer_id, external.signer_a.public_key, external.signer_a.key_version)
            binding_b = ExternalSignerBinding("B", external.signer_b.endpoint, external.signer_b.signer_id, external.signer_b.public_key, external.signer_b.key_version)
            pair = ExternalFixedRoleSignerPair(binding_a, binding_b, timeout_seconds=external.timeout_seconds)
            journal = SigningJournal(external.journal_path)
            validator = ExternalThresholdBundleValidator(journal=journal, signer_a=binding_a, signer_b=binding_b)
            builder = SettlementTransactionBuilder(coordinator_state=state, signing_journal=journal, threshold_signer=validator, solana_runtime=config.solana)
            simulation = SettlementSimulationService.from_runtime_config(builder=builder, runtime_config=config)
            submission = SettlementSubmissionService.from_runtime_config(runtime_config=config, simulation_service=simulation, signing_journal=journal)
            executor = ProductionSettlementExecutor(state=state, runtime_config=config, signer_pair=pair, journal=journal, bundle_validator=validator, simulation_service=simulation, submission_service=submission)
            resources.append(executor)
        return create_coordinator_service(
            coordinator=coordinator,
            state=state,
            auth_token=token,
            request_max_bytes=config.limits.request_max_bytes,
            request_timeout_seconds=config.coordinator.request_timeout_seconds,
            close_resources=True,
            solana_runtime=config.solana if require_settlement_context else None,
            require_settlement_context=require_settlement_context,
            settlement_executor=executor,
        )
    except Exception:
        for resource in reversed(resources):
            close = getattr(resource, "close", None)
            if close is not None:
                close()
        return create_coordinator_service(
            request_max_bytes=1,
            request_timeout_seconds=1,
            startup_error="startup_invalid",
        )
