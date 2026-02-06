import json
import hashlib
from typing import Any, Dict, Union
from pydantic import BaseModel, Field
from .types import OutcomeEnum

class ResolverDefinition(BaseModel):
    url: str
    method: str = "GET"
    path: str = Field(..., description="Dot-separated JSON path to value (e.g. 'data.price')")
    predicate: str = Field(..., pattern="^(equals|contains|gt|gte|lt|lte)$")
    target_value: Union[str, int, float, bool]

def compute_resolver_hash(definition: dict) -> bytes:
    """
    Computes the canonical SHA256 hash of a resolver definition.
    Keys are sorted, no whitespace in separators.
    """
    canonical_json = json.dumps(
        definition, 
        sort_keys=True, 
        separators=(',', ':')
    )
    return hashlib.sha256(canonical_json.encode('utf-8')).digest()

def resolver_hash_hex(definition: dict) -> str:
    return compute_resolver_hash(definition).hex()

def extract_value(data: Any, path: str) -> Any:
    """
    Extracts value from nested dict using dot notation.
    """
    keys = path.split('.')
    current = data
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        else:
            return None
    return current

def evaluate_resolver(definition: ResolverDefinition, public_inputs: Dict[str, Any]) -> OutcomeEnum:
    """
    Evaluates the resolver logic against the provided public inputs.
    Returns YES, NO, or INVALID.
    """
    try:
        actual_value = extract_value(public_inputs, definition.path)
        
        if actual_value is None:
            # Path not found in public inputs
            return OutcomeEnum.INVALID

        target = definition.target_value
        pred = definition.predicate

        # Type Safety: Ensure types are comparable
        # If target is int/float, try to cast actual.
        if isinstance(target, (int, float)):
            try:
                actual_value = float(actual_value)
                target = float(target)
            except (ValueError, TypeError):
                return OutcomeEnum.INVALID

        is_match = False
        
        if pred == "equals":
            is_match = (actual_value == target)
        elif pred == "contains":
            is_match = (str(target) in str(actual_value))
        elif pred == "gt":
            is_match = (actual_value > target)
        elif pred == "gte":
            is_match = (actual_value >= target)
        elif pred == "lt":
            is_match = (actual_value < target)
        elif pred == "lte":
            is_match = (actual_value <= target)
        else:
            return OutcomeEnum.INVALID

        return OutcomeEnum.YES if is_match else OutcomeEnum.NO

    except Exception:
        # Any unexpected error during eval treats inputs as invalid
        return OutcomeEnum.INVALID