import base64
import json

import httpx
import pytest

from src.proof_fetcher import HttpProofFetcher, ProofFetchError
from src.resolver import compute_resolver_hash
from src.resolver_registry import (
    HttpResolverRegistry,
    ResolverRegistryMalformedResponse,
    ResolverRegistryResponseTooLarge,
)


class _Response:
    def __init__(self, chunks, *, headers=None, status_code=200):
        self._chunks = list(chunks)
        self.headers = headers or {}
        self.status_code = status_code

    def iter_bytes(self):
        yield from self._chunks


def test_proof_raw_response_exact_boundary():
    fetcher = HttpProofFetcher(
        response_max_bytes=8,
        proof_max_bytes=8,
        public_inputs_max_bytes=8,
    )
    assert fetcher._read_bounded_response(_Response([b"1234", b"5678"]), 8) == b"12345678"


def test_proof_raw_response_limit_plus_one_aborts_without_reading_more():
    fetcher = HttpProofFetcher(
        response_max_bytes=8,
        proof_max_bytes=8,
        public_inputs_max_bytes=8,
    )
    consumed = []

    class Response:
        headers = {}
        status_code = 200

        def iter_bytes(self):
            consumed.append(1)
            yield b"12345678"
            consumed.append(2)
            yield b"9"
            pytest.fail("reader must abort immediately after overflow")

    with pytest.raises(ProofFetchError) as exc:
        fetcher._read_bounded_response(Response(), 8)
    assert exc.value.code == "http_response_too_large"
    assert consumed == [1, 2]


@pytest.mark.parametrize(
    ("label", "limit", "value", "expected_code"),
    [
        ("proof", 3, base64.b64encode(b"abc").decode(), None),
        ("proof", 3, base64.b64encode(b"abcd").decode(), "proof_too_large"),
        ("public_inputs", 3, base64.b64encode(b"abc").decode(), None),
        (
            "public_inputs",
            3,
            base64.b64encode(b"abcd").decode(),
            "public_inputs_too_large",
        ),
    ],
)
def test_decoded_base64_boundaries(label, limit, value, expected_code):
    if expected_code is None:
        assert HttpProofFetcher._decode_b64_bounded(
            value,
            max_bytes=limit,
            label=label,
        ) == b"abc"
        return
    with pytest.raises(ProofFetchError) as exc:
        HttpProofFetcher._decode_b64_bounded(
            value,
            max_bytes=limit,
            label=label,
        )
    assert exc.value.code == expected_code


def test_malformed_proof_base64_rejected():
    with pytest.raises(ProofFetchError) as exc:
        HttpProofFetcher._decode_b64_bounded(
            "%%%not-base64%%%",
            max_bytes=64,
            label="proof",
        )
    assert exc.value.code == "malformed_base64"


def _resolver_definition():
    return {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }


def test_registry_response_exact_boundary():
    registry = HttpResolverRegistry("https://registry.example/resolvers", "", 1.0, 8)
    assert registry._read_bounded_response(_Response([b"1234", b"5678"])) == b"12345678"


def test_registry_response_oversized():
    registry = HttpResolverRegistry("https://registry.example/resolvers", "", 1.0, 8)
    with pytest.raises(ResolverRegistryResponseTooLarge):
        registry._read_bounded_response(_Response([b"12345678", b"9"]))


def test_registry_response_declared_oversized():
    registry = HttpResolverRegistry("https://registry.example/resolvers", "", 1.0, 8)
    with pytest.raises(ResolverRegistryResponseTooLarge):
        registry._read_bounded_response(
            _Response([b"{}"], headers={"content-length": "9"})
        )


def test_registry_response_malformed_content_length():
    registry = HttpResolverRegistry("https://registry.example/resolvers", "", 1.0, 8)
    with pytest.raises(ResolverRegistryMalformedResponse):
        registry._read_bounded_response(
            _Response([b"{}"], headers={"content-length": "NaN"})
        )


def test_registry_malformed_json_within_limit(monkeypatch):
    raw = b"{not-json"
    requested_hash = bytes([7] * 32)

    class Stream:
        def __enter__(self):
            req = httpx.Request("GET", "https://registry.example/test")
            self.response = httpx.Response(200, content=raw, request=req)
            return self.response

        def __exit__(self, *args):
            return False

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return Stream()

    monkeypatch.setattr(httpx, "Client", Client)
    registry = HttpResolverRegistry(
        "https://registry.example/resolvers",
        "",
        1.0,
        len(raw),
    )
    with pytest.raises(ResolverRegistryMalformedResponse):
        registry.load(requested_hash)


def test_registry_bounded_valid_response_with_correct_hash(monkeypatch):
    resolver = _resolver_definition()
    resolver_hash = compute_resolver_hash(resolver)
    raw = json.dumps({"resolver": resolver}, separators=(",", ":")).encode()

    class Stream:
        def __enter__(self):
            req = httpx.Request("GET", "https://registry.example/test")
            self.response = httpx.Response(200, content=raw, request=req)
            return self.response

        def __exit__(self, *args):
            return False

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return Stream()

    monkeypatch.setattr(httpx, "Client", Client)
    registry = HttpResolverRegistry(
        "https://registry.example/resolvers",
        "",
        1.0,
        len(raw),
    )
    loaded = registry.load(resolver_hash)
    assert loaded.path == resolver["path"]


def test_registry_valid_json_wrong_content_hash_still_rejected(monkeypatch):
    resolver = _resolver_definition()
    raw = json.dumps(resolver, separators=(",", ":")).encode()

    class Stream:
        def __enter__(self):
            req = httpx.Request("GET", "https://registry.example/test")
            self.response = httpx.Response(200, content=raw, request=req)
            return self.response

        def __exit__(self, *args):
            return False

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return Stream()

    monkeypatch.setattr(httpx, "Client", Client)
    registry = HttpResolverRegistry(
        "https://registry.example/resolvers",
        "",
        1.0,
        len(raw),
    )
    with pytest.raises(ValueError):
        registry.load(bytes([9] * 32))
