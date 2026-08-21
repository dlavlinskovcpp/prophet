import base64
from typing import Dict, Any, Tuple, Union, List
from dataclasses import asdict
from ..resolver import ResolverDefinition

# Keys to strictly filter out from meta responses (case-sensitive)
SCRUB_DROP_EXACT = {"proof", "public_inputs", "raw"}
MAX_STRING_LEN = 2048
MAX_DEPTH = 4

def _scrub_value(obj: Any, depth: int) -> Any:
    """
    Recursively sanitizes values to ensure safety for logging/storage.
    """
    if depth > MAX_DEPTH:
        return "[Depth Limit]"

    if isinstance(obj, dict):
        new_dict = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                continue # Key must be string
            
            # 1. Drop specific unsafe keys
            if k.endswith("_b64") or k in SCRUB_DROP_EXACT:
                continue
            
            # 2. Recurse
            sanitized = _scrub_value(v, depth + 1)
            
            # 3. Drop nulls or empty scrubbed results if desired, or keep. Keeping for now.
            new_dict[k] = sanitized
        return new_dict

    elif isinstance(obj, list):
        return [_scrub_value(item, depth + 1) for item in obj]

    elif isinstance(obj, str):
        if len(obj) > MAX_STRING_LEN:
            return obj[:MAX_STRING_LEN] + "...[Truncated]"
        return obj

    elif isinstance(obj, (int, float, bool, type(None))):
        return obj

    else:
        # Unknown type (e.g. objects), convert to string safe
        s = str(obj)
        if len(s) > MAX_STRING_LEN:
            return s[:MAX_STRING_LEN] + "...[Truncated]"
        return s

def build_verify_payload(
    resolver: ResolverDefinition, 
    proof_bytes: bytes, 
    public_inputs_bytes: bytes
) -> Dict[str, Any]:
    """
    Constructs the standard JSON payload for the Reclaim HTTP Verifier.
    """
    # 1. Restrict Resolver Fields exactly
    safe_resolver = {
        "url": resolver.url,
        "method": resolver.method,
        "path": resolver.path,
        "predicate": resolver.predicate,
        "target_value": resolver.target_value
    }
    
    proof_b64 = base64.b64encode(proof_bytes).decode("utf-8")
    pi_b64 = base64.b64encode(public_inputs_bytes).decode("utf-8")
    
    return {
        "resolver": safe_resolver,
        "proof_bytes_b64": proof_b64,
        "public_inputs_bytes_b64": pi_b64,
        "proof_len": len(proof_bytes),
        "public_inputs_len": len(public_inputs_bytes)
    }

def _strict_verification_status(data: Dict[str, Any]) -> Tuple[bool, str]:
    present = []
    for key in ("ok", "valid"):
        if key not in data:
            continue
        value = data[key]
        if type(value) is not bool:
            return False, "invalid_verification_status_type"
        present.append(value)

    if not present:
        return False, "missing_verification_status"
    if len(set(present)) != 1:
        return False, "conflicting_verification_status"
    return present[0], ""


def parse_verify_response(data: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Parses the Reclaim HTTP response.
    Returns (is_valid, reason, sanitized_meta).

    Verification status is intentionally strict: only actual JSON booleans are
    accepted. Strings/numbers/null and conflicting ok/valid fields fail closed.
    """
    if not isinstance(data, dict):
        return False, "invalid_verification_response", {}

    is_valid, status_error = _strict_verification_status(data)

    reason = ""
    if not is_valid:
        reason = status_error or str(
            data.get("reason", "")
            or data.get("error", "Unknown verification failure")
        )

    # Full recursive scrub
    sanitized_root = _scrub_value(data, 0)

    # Ensure root is a dict (scrub can return other types if input wasn't dict, but data type hint says Dict)
    if not isinstance(sanitized_root, dict):
        sanitized_root = {}

    # Remove status fields from meta to avoid redundancy
    for key in ["ok", "valid", "reason", "error"]:
        sanitized_root.pop(key, None)

    return is_valid, reason, sanitized_root