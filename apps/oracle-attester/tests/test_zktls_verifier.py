import pytest
import httpx
from src.zktls_verifier import ReclaimHttpVerifier, make_verifier
from src.resolver import ResolverDefinition
from src.config import settings

def test_make_verifier_rejects_unsupported_mode(monkeypatch):
    monkeypatch.setattr(settings, "ZKTLS_MODE", "mock")
    with pytest.raises(ValueError):
        make_verifier()

def test_reclaim_http_verifier_ok_and_fail(monkeypatch):
    settings.RECLAIM_VERIFY_URL = "http://mock-reclaim.test"
    verifier = ReclaimHttpVerifier()
    res_def = ResolverDefinition(url="x", path="x", predicate="equals", target_value=1)

    # 1. Simulate OK response
    class MockClientOk:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, json=None, headers=None):
            req = httpx.Request("POST", url)
            return httpx.Response(200, json={"valid": True, "id": "123", "ignore_b64": "bytes"}, request=req)

    monkeypatch.setattr(httpx, "Client", MockClientOk)
    
    res = verifier.verify(resolver=res_def, proof_bytes=b"p", public_inputs_bytes=b"{}")
    assert res.ok
    assert res.meta.get("id") == "123"
    # Ensure no raw bytes leaked into meta if present in response
    assert not any(k.endswith("_b64") for k in (res.meta or {}).keys())

    # 2. Simulate FAIL response
    class MockClientFail:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, json=None, headers=None):
            req = httpx.Request("POST", url)
            return httpx.Response(200, json={"valid": False, "reason": "bad_sig"}, request=req)

    monkeypatch.setattr(httpx, "Client", MockClientFail)
    
    res = verifier.verify(resolver=res_def, proof_bytes=b"p", public_inputs_bytes=b"{}")
    assert not res.ok
    assert res.reason == "bad_sig"

    # 3. Simulate HTTP Error
    class MockClientError:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def post(self, url, json=None, headers=None):
            raise httpx.ConnectError("Network down")

    monkeypatch.setattr(httpx, "Client", MockClientError)
    res = verifier.verify(resolver=res_def, proof_bytes=b"p", public_inputs_bytes=b"{}")
    assert not res.ok
    assert "http_error" in res.reason


def test_reclaim_http_verifier_requires_non_empty_payload():
    settings.RECLAIM_VERIFY_URL = "http://mock-reclaim.test"
    verifier = ReclaimHttpVerifier()
    res_def = ResolverDefinition(url="x", path="x", predicate="equals", target_value=1)

    missing_proof = verifier.verify(resolver=res_def, proof_bytes=b"", public_inputs_bytes=b"{}")
    assert not missing_proof.ok
    assert missing_proof.reason == "missing_proof"

    missing_pi = verifier.verify(resolver=res_def, proof_bytes=b"proof", public_inputs_bytes=b"")
    assert not missing_pi.ok
    assert missing_pi.reason == "missing_public_inputs"
