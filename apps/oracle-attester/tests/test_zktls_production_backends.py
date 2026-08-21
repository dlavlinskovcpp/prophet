import hashlib
import json

from src.independent_zktls_runtime_factory import BoundHttpIndependentProofChecker
from src.resolver_v2_adapters import ZkTlsExpectedBinding
from src.zktls_runtime_backend import BoundHttpZkTlsProofVerifier


class Response:
    def __init__(self, payload):
        self._raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.headers = {}

    def raise_for_status(self):
        return None

    def iter_bytes(self, chunk_size=None):
        yield self._raw


class StreamContext:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, *_args):
        return None


def _binding():
    return ZkTlsExpectedBinding(
        resolver_id="r",
        definition_hash="01" * 32,
        source_domain="api.example",
        request_definition_hash="02" * 32,
        cluster_genesis_hash="03" * 32,
        proof_version="1",
        acquired_at_ms="10",
        evidence_payload_hash="04" * 32,
    )


def test_primary_production_http_backend_returns_bound_claims(monkeypatch):
    response_bytes = b'{"ok":true}'
    binding = _binding()
    payload = {
        "valid": True,
        "proof_version": binding.proof_version,
        "source_domain": binding.source_domain,
        "request_definition_hash": binding.request_definition_hash,
        "cluster_genesis_hash": binding.cluster_genesis_hash,
        "response_hash": hashlib.sha256(response_bytes).hexdigest(),
        "reason": "",
    }

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def stream(self, *_args, **_kwargs):
            return StreamContext(Response(payload))

    monkeypatch.setattr("src.zktls_runtime_backend.httpx.Client", Client)
    result = BoundHttpZkTlsProofVerifier(
        url="https://primary.example/verify",
        token="a",
        timeout_seconds=5,
        max_response_bytes=4096,
    ).verify(
        proof_bytes=b"proof",
        response_bytes=response_bytes,
        expected_binding=binding,
    )
    assert result.valid is True
    assert result.response_hash == payload["response_hash"]


def test_independent_production_backend_uses_separate_parser_and_contract(monkeypatch):
    response_bytes = b'{"ok":true}'
    payload = {
        "valid": True,
        "proof_version": "1",
        "source_domain": "api.example",
        "request_definition_hash": "02" * 32,
        "cluster_genesis_hash": "03" * 32,
        "response_hash": hashlib.sha256(response_bytes).hexdigest(),
    }
    monkeypatch.setattr(
        "src.independent_zktls_runtime_factory.httpx.stream",
        lambda *_args, **_kwargs: StreamContext(Response(payload)),
    )
    result = BoundHttpIndependentProofChecker(
        url="https://independent.example/verify",
        token="b",
        timeout_seconds=5,
        max_response_bytes=4096,
    ).validate(b"proof", response_bytes)
    assert result.accepted is True
    assert result.response_digest == payload["response_hash"]
