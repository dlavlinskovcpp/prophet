import pytest
import base64
from src.zktls_providers.reclaim_http import build_verify_payload, parse_verify_response
from src.resolver import ResolverDefinition

def test_build_payload_strict_resolver_fields():
    # Resolver definition with extra potential internal fields? 
    # Since ResolverDefinition is Pydantic/Dataclass, it's fixed.
    # But let's verify build_verify_payload output keys.
    
    res_def = ResolverDefinition(url="http://x", path="a", predicate="equals", target_value=1)
    proof = b"p"
    pi = b"i"
    
    payload = build_verify_payload(res_def, proof, pi)
    
    res_out = payload["resolver"]
    # Must contain exactly these 5 keys
    expected_keys = {"url", "method", "path", "predicate", "target_value"}
    assert set(res_out.keys()) == expected_keys

def test_parse_response_recursive_scrub():
    # Complex response with nested unsafe keys and large strings
    huge_str = "A" * 3000
    
    raw_resp = {
        "valid": True,
        "id": "verify-123",
        "proof_bytes_b64": "SGVsbG8=", # Should be dropped (root)
        "debug": {
            "inner_b64": "SGVsbG8=",   # Should be dropped (nested)
            "safe": 1,
            "deep": {
                "unsafe_b64": "x",     # Dropped
                "ok": "val"
            }
        },
        "raw": "sensitive",            # Dropped (exact match)
        "large_log": huge_str          # Truncated
    }
    
    ok, reason, meta = parse_verify_response(raw_resp)
    
    assert ok is True
    assert reason == ""
    
    # 1. Root checks
    assert "proof_bytes_b64" not in meta
    assert "raw" not in meta
    assert meta["id"] == "verify-123"
    
    # 2. Nested checks
    assert "inner_b64" not in meta["debug"]
    assert meta["debug"]["safe"] == 1
    assert "unsafe_b64" not in meta["debug"]["deep"]
    assert meta["debug"]["deep"]["ok"] == "val"
    
    # 3. Truncation
    assert len(meta["large_log"]) < 3000
    assert meta["large_log"].endswith("...[Truncated]")

def test_parse_response_fail_reason():
    raw_resp = {
        "valid": False,
        "reason": "signature_invalid",
        "error_code": 1001
    }
    
    ok, reason, meta = parse_verify_response(raw_resp)
    
    assert ok is False
    assert reason == "signature_invalid"
    # Reason is removed from meta, error_code remains
    assert "reason" not in meta
    assert meta["error_code"] == 1001