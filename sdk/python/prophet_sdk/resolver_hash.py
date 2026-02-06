import json
import hashlib
from typing import Any, Dict, Union

def canonical_resolver_json(defn: Dict[str, Any]) -> str:
    """
    Returns the canonical JSON string representation of a resolver definition.
    Keys are sorted, separators are compact (no whitespace).
    """
    return json.dumps(defn, sort_keys=True, separators=(',', ':'))

def compute_resolver_hash(defn: Dict[str, Any]) -> bytes:
    """
    Computes the SHA256 hash of the canonical resolver JSON.
    Returns 32 bytes.
    """
    json_str = canonical_resolver_json(defn)
    return hashlib.sha256(json_str.encode('utf-8')).digest()

def compute_resolver_hash_hex(defn: Dict[str, Any]) -> str:
    """
    Computes the SHA256 hash of the canonical resolver JSON.
    Returns hex string.
    """
    return compute_resolver_hash(defn).hex()

def load_resolver_definition(path: str) -> Dict[str, Any]:
    """
    Loads a resolver definition from a JSON file.
    """
    with open(path, 'r') as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Resolver definition at {path} must be a JSON object")
    return data