import hashlib
import json
from typing import Union, Dict, Any


def normalize_public_inputs(inputs: Union[Dict[str, Any], str, bytes]) -> bytes:
    if isinstance(inputs, bytes):
        return inputs
    if isinstance(inputs, str):
        return inputs.encode("utf-8")
    if isinstance(inputs, dict):
        return json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode("utf-8")
    raise ValueError(f"Unsupported public inputs type: {type(inputs)}")


def calculate_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def verify_hash_integrity(data_bytes: bytes, expected_hash_bytes: bytes) -> bool:
    return calculate_hash(data_bytes) == expected_hash_bytes
