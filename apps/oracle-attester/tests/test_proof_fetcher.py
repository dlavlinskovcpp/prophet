import pytest
import os
import base64
import httpx
from src.proof_fetcher import LocalFileProofFetcher, HttpProofFetcher, FetchedProof
from src.config import settings

def test_local_file_fetcher(tmp_path):
    # Create dummy files
    p_file = tmp_path / "proof.bin"
    p_file.write_bytes(b"proofdata")
    
    pi_file = tmp_path / "pi.bin"
    pi_file.write_bytes(b"pidata")
    
    fetcher = LocalFileProofFetcher()
    ref = f"file:{p_file}:{pi_file}"
    
    res = fetcher.fetch(ref)
    
    assert res.proof_bytes == b"proofdata"
    assert res.public_inputs_bytes == b"pidata"
    assert res.provider == "local_files"
    assert res.meta["proof_size"] == 9

def test_http_fetcher_ok(monkeypatch):
    settings.PROOF_FETCH_URL = "http://mock-provider.test"
    
    # Mock Response
    mock_json = {
        "proof_b64": base64.b64encode(b"httpproof").decode(),
        "public_inputs_b64": base64.b64encode(b"httppi").decode(),
        "extra_meta": "keepme"
    }
    
    class MockClient:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, params=None, headers=None):
            req = httpx.Request("GET", url)
            return httpx.Response(200, json=mock_json, request=req)

    monkeypatch.setattr(httpx, "Client", MockClient)
    
    fetcher = HttpProofFetcher()
    res = fetcher.fetch("ref-123")
    
    assert res.proof_bytes == b"httpproof"
    assert res.public_inputs_bytes == b"httppi"
    assert res.provider == "http_fetch"
    assert res.meta["extra_meta"] == "keepme"
    
    # Ensure raw b64 strings are scrubbed
    assert "proof_b64" not in res.meta
    assert "public_inputs_b64" not in res.meta