import gzip
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest

from src.bounded_http_response import (
    BoundedHttpResponseTooLarge,
    read_bounded_response_bytes,
)
from src.independent_zktls_runtime_factory import (
    BoundHttpIndependentProofChecker,
    IndependentZkTlsRuntimeFactory,
)
from src.resolver_v2_adapters import ZkTlsExpectedBinding
from src.resolver_v2_pipeline import PipelineRejected
from src.zktls_runtime_backend import (
    BoundHttpZkTlsProofVerifier,
    make_zktls_proof_verifier,
)


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


def _primary_payload(response_bytes=b'{"ok":true}'):
    binding = _binding()
    return {
        "valid": True,
        "proof_version": binding.proof_version,
        "source_domain": binding.source_domain,
        "request_definition_hash": binding.request_definition_hash,
        "cluster_genesis_hash": binding.cluster_genesis_hash,
        "response_hash": hashlib.sha256(response_bytes).hexdigest(),
        "reason": "",
    }


def _independent_payload(response_bytes=b'{"ok":true}'):
    return {
        "valid": True,
        "proof_version": "1",
        "source_domain": "api.example",
        "request_definition_hash": "02" * 32,
        "cluster_genesis_hash": "03" * 32,
        "response_hash": hashlib.sha256(response_bytes).hexdigest(),
    }


class StreamingResponse:
    def __init__(self, chunks, *, headers=None, status_code=200):
        self._chunks = list(chunks)
        self.headers = dict(headers or {})
        self.status_code = status_code
        self.chunks_read = 0
        request = httpx.Request("POST", "https://verifier.example/verify")
        self._httpx_response = httpx.Response(status_code, request=request)

    def raise_for_status(self):
        self._httpx_response.raise_for_status()

    def iter_bytes(self, chunk_size=None):
        for chunk in self._chunks:
            self.chunks_read += 1
            yield chunk


class StreamContext:
    def __init__(self, response=None, *, enter_error=None):
        self.response = response
        self.enter_error = enter_error

    def __enter__(self):
        if self.enter_error is not None:
            raise self.enter_error
        return self.response

    def __exit__(self, *_args):
        return None


def _install_primary(monkeypatch, stream_context):
    class Client:
        def __init__(self, **kwargs):
            assert kwargs["timeout"] == 5

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, method, url, **kwargs):
            assert method == "POST"
            assert url == "https://primary.example/verify"
            assert kwargs["headers"]["Authorization"] == "Bearer primary-token"
            return stream_context

    monkeypatch.setattr("src.zktls_runtime_backend.httpx.Client", Client)


def _primary(max_response_bytes):
    return BoundHttpZkTlsProofVerifier(
        url="https://primary.example/verify",
        token="primary-token",
        timeout_seconds=5,
        max_response_bytes=max_response_bytes,
    )


def _install_independent(monkeypatch, stream_context):
    def stream(method, url, **kwargs):
        assert method == "POST"
        assert url == "https://independent.example/verify"
        assert kwargs["headers"]["Authorization"] == "Bearer independent-token"
        assert kwargs["timeout"] == 5
        return stream_context

    monkeypatch.setattr("src.independent_zktls_runtime_factory.httpx.stream", stream)


def _independent(max_response_bytes):
    return BoundHttpIndependentProofChecker(
        url="https://independent.example/verify",
        token="independent-token",
        timeout_seconds=5,
        max_response_bytes=max_response_bytes,
    )


def _raw(payload):
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def test_primary_valid_bounded_response_succeeds(monkeypatch):
    raw = _raw(_primary_payload())
    _install_primary(monkeypatch, StreamContext(StreamingResponse([raw])))
    claims = _primary(len(raw)).verify(
        proof_bytes=b"proof",
        response_bytes=b'{"ok":true}',
        expected_binding=_binding(),
    )
    assert claims.valid is True


def test_primary_exact_boundary_reaches_semantic_parser(monkeypatch):
    raw = _raw({"valid": True})
    _install_primary(monkeypatch, StreamContext(StreamingResponse([raw])))
    with pytest.raises(PipelineRejected, match="runtime_zktls_http_response_invalid"):
        _primary(len(raw)).verify(
            proof_bytes=b"proof",
            response_bytes=b"response",
            expected_binding=_binding(),
        )


def test_primary_max_plus_one_rejected_before_semantic_parser_and_stops_reading(monkeypatch):
    response = StreamingResponse([b"x" * 8, b"y", b"secret-body"])
    _install_primary(monkeypatch, StreamContext(response))
    with pytest.raises(PipelineRejected, match="runtime_zktls_http_response_too_large") as excinfo:
        _primary(8).verify(
            proof_bytes=b"proof",
            response_bytes=b"response",
            expected_binding=_binding(),
        )
    assert response.chunks_read == 2
    assert "secret-body" not in str(excinfo.value)
    assert "secret-body" not in repr(excinfo.value)


def test_primary_missing_content_length_oversized_stream_rejected(monkeypatch):
    response = StreamingResponse([b"1234", b"56789"])
    _install_primary(monkeypatch, StreamContext(response))
    with pytest.raises(PipelineRejected, match="runtime_zktls_http_response_too_large"):
        _primary(8).verify(
            proof_bytes=b"proof",
            response_bytes=b"response",
            expected_binding=_binding(),
        )


def test_primary_misleading_small_content_length_cannot_bypass(monkeypatch):
    response = StreamingResponse([b"1234", b"56789"], headers={"content-length": "1"})
    _install_primary(monkeypatch, StreamContext(response))
    with pytest.raises(PipelineRejected, match="runtime_zktls_http_response_too_large"):
        _primary(8).verify(
            proof_bytes=b"proof",
            response_bytes=b"response",
            expected_binding=_binding(),
        )


def test_primary_malformed_json_within_bound_rejected(monkeypatch):
    raw = b"{not-json}"
    _install_primary(monkeypatch, StreamContext(StreamingResponse([raw])))
    with pytest.raises(PipelineRejected, match="runtime_zktls_http_response_invalid"):
        _primary(len(raw)).verify(
            proof_bytes=b"proof",
            response_bytes=b"response",
            expected_binding=_binding(),
        )


def test_primary_non_2xx_remains_fail_closed(monkeypatch):
    response = StreamingResponse([b'{"error":"down"}'], status_code=503)
    _install_primary(monkeypatch, StreamContext(response))
    with pytest.raises(PipelineRejected, match="runtime_zktls_http_verifier_unavailable"):
        _primary(4096).verify(
            proof_bytes=b"proof",
            response_bytes=b"response",
            expected_binding=_binding(),
        )
    assert response.chunks_read == 0


def test_primary_timeout_behavior_unchanged(monkeypatch):
    timeout = httpx.ReadTimeout("timed out")
    _install_primary(monkeypatch, StreamContext(enter_error=timeout))
    with pytest.raises(PipelineRejected, match="runtime_zktls_http_verifier_unavailable"):
        _primary(4096).verify(
            proof_bytes=b"proof",
            response_bytes=b"response",
            expected_binding=_binding(),
        )


def test_primary_semantic_validation_still_runs_after_bounded_parse(monkeypatch):
    payload = _primary_payload()
    payload["valid"] = "true"
    raw = _raw(payload)
    _install_primary(monkeypatch, StreamContext(StreamingResponse([raw])))
    with pytest.raises(PipelineRejected, match="runtime_zktls_http_response_invalid"):
        _primary(len(raw)).verify(
            proof_bytes=b"proof",
            response_bytes=b"response",
            expected_binding=_binding(),
        )


def test_independent_valid_bounded_response_succeeds(monkeypatch):
    response_bytes = b'{"ok":true}'
    raw = _raw(_independent_payload(response_bytes))
    _install_independent(monkeypatch, StreamContext(StreamingResponse([raw])))
    claims = _independent(len(raw)).validate(b"proof", response_bytes)
    assert claims.accepted is True


def test_independent_oversized_response_rejected(monkeypatch):
    response = StreamingResponse([b"12345678", b"9", b"never-read"])
    _install_independent(monkeypatch, StreamContext(response))
    with pytest.raises(PipelineRejected, match="independent_zktls_response_too_large"):
        _independent(8).validate(b"proof", b"response")
    assert response.chunks_read == 2


def test_independent_missing_content_length_cannot_bypass(monkeypatch):
    response = StreamingResponse([b"1234", b"56789"])
    _install_independent(monkeypatch, StreamContext(response))
    with pytest.raises(PipelineRejected, match="independent_zktls_response_too_large"):
        _independent(8).validate(b"proof", b"response")


def test_independent_misleading_content_length_cannot_bypass(monkeypatch):
    response = StreamingResponse([b"1234", b"56789"], headers={"content-length": "1"})
    _install_independent(monkeypatch, StreamContext(response))
    with pytest.raises(PipelineRejected, match="independent_zktls_response_too_large"):
        _independent(8).validate(b"proof", b"response")


def test_independent_malformed_json_rejected(monkeypatch):
    raw = b"{not-json}"
    _install_independent(monkeypatch, StreamContext(StreamingResponse([raw])))
    with pytest.raises(PipelineRejected, match="independent_zktls_response_invalid"):
        _independent(len(raw)).validate(b"proof", b"response")


def test_independent_semantic_contract_remains_separate(monkeypatch):
    payload = _independent_payload()
    payload["reason"] = ""
    raw = _raw(payload)
    _install_independent(monkeypatch, StreamContext(StreamingResponse([raw])))
    with pytest.raises(PipelineRejected, match="independent_zktls_response_invalid"):
        _independent(len(raw)).validate(b"proof", b"response")


def test_decoded_decompressed_bytes_are_counted_not_compressed_transport_bytes():
    decoded = b'{"value":"' + (b"a" * 4096) + b'"}'
    compressed = gzip.compress(decoded)
    assert len(compressed) < len(decoded)
    request = httpx.Request("GET", "https://verifier.example/result")
    response = httpx.Response(
        200,
        content=compressed,
        headers={
            "content-encoding": "gzip",
            "content-length": str(len(compressed)),
        },
        request=request,
    )
    max_bytes = max(len(compressed), 128)
    assert max_bytes < len(decoded)
    with pytest.raises(BoundedHttpResponseTooLarge):
        read_bounded_response_bytes(response, max_bytes=max_bytes)


def test_primary_factory_reuses_runtime_request_max_bytes_for_response_cap(monkeypatch):
    monkeypatch.setenv("PROPHET_ZKTLS_VERIFY_URL", "https://primary.example/verify")
    monkeypatch.setenv("PROPHET_ZKTLS_VERIFY_TOKEN", "primary-token")
    runtime = SimpleNamespace(
        zktls=SimpleNamespace(verifier_backend="bound-http"),
        allowed_adapters=("zktls",),
        mode="production",
        limits=SimpleNamespace(request_timeout_seconds=5, request_max_bytes=321),
    )
    verifier = make_zktls_proof_verifier(runtime)
    assert verifier._max_response_bytes == 321


def test_independent_factory_reuses_runtime_request_max_bytes_for_response_cap():
    checker = BoundHttpIndependentProofChecker(
        url="https://independent.example/verify",
        token="independent-token",
        timeout_seconds=5,
    )
    descriptor = {
        "schema": "prophet.adapter-descriptor.v2",
        "schema_version": "2.0.0",
        "adapter_id": "prophet.verifier.runtime.b",
        "adapter_version": "2.0.0",
        "implementation_digest": "47" * 32,
    }
    runtime = SimpleNamespace(
        verifier=SimpleNamespace(
            implementation_id=descriptor["adapter_id"],
            version=descriptor["adapter_version"],
        ),
        allowed_adapters=("zktls",),
        zktls=object(),
        limits=SimpleNamespace(request_max_bytes=654),
    )
    factory = IndependentZkTlsRuntimeFactory(
        runtime_config=runtime,
        verifier_descriptor=descriptor,
        checker=checker,
    )
    assert factory.checker is not checker
    assert factory.checker._max_response_bytes == 654


def test_independent_non_2xx_remains_fail_closed(monkeypatch):
    response = StreamingResponse([b'{"error":"down"}'], status_code=503)
    _install_independent(monkeypatch, StreamContext(response))
    with pytest.raises(PipelineRejected, match="independent_zktls_verifier_unavailable"):
        _independent(4096).validate(b"proof", b"response")
    assert response.chunks_read == 0


def test_independent_timeout_behavior_unchanged(monkeypatch):
    timeout = httpx.ReadTimeout("timed out")
    _install_independent(monkeypatch, StreamContext(enter_error=timeout))
    with pytest.raises(PipelineRejected, match="independent_zktls_verifier_unavailable"):
        _independent(4096).validate(b"proof", b"response")
