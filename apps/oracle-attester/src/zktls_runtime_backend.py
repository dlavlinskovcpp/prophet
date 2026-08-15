"""Allowlisted zkTLS proof-verifier backends for verifier runtimes only."""
from __future__ import annotations

import hashlib
from typing import Any

from .resolver_v2_adapters import ZkTlsClaims, ZkTlsExpectedBinding, ZkTlsProofVerifier
from .resolver_v2_pipeline import PipelineRejected


DETERMINISTIC_TEST_BACKEND = "deterministic-test"


class DeterministicTestZkTlsProofVerifier:
    """Test-only backend for the explicit `b"proof"` fixture contract."""

    backend_id = DETERMINISTIC_TEST_BACKEND

    def verify(self, *, proof_bytes: bytes, response_bytes: bytes, expected_binding: ZkTlsExpectedBinding) -> ZkTlsClaims:
        valid = proof_bytes == b"proof" and bool(response_bytes)
        return ZkTlsClaims(
            valid=valid,
            proof_version=expected_binding.proof_version,
            source_domain=expected_binding.source_domain,
            request_definition_hash=expected_binding.request_definition_hash,
            cluster_genesis_hash=expected_binding.cluster_genesis_hash,
            response_hash=hashlib.sha256(response_bytes).hexdigest(),
            reason="deterministic_test_proof_invalid" if not valid else "",
        )


def make_zktls_proof_verifier(runtime_config: Any) -> ZkTlsProofVerifier:
    """Resolve only explicit allowlisted backends; no fallback exists."""
    configured = getattr(runtime_config, "zktls", None)
    if configured is None or "zktls" not in getattr(runtime_config, "allowed_adapters", ()):
        raise PipelineRejected("runtime_zktls_not_enabled")
    if configured.verifier_backend != DETERMINISTIC_TEST_BACKEND:
        raise PipelineRejected("runtime_zktls_backend_unavailable")
    if getattr(runtime_config, "mode", None) != "test":
        raise PipelineRejected("runtime_zktls_test_backend_not_allowed")
    return DeterministicTestZkTlsProofVerifier()
