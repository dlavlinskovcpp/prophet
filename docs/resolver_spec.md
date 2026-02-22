# Resolver Specification & Hashing

This document defines the canonical format for defining a Prophet resolver and computing its unique `resolver_hash`.

## Resolver Definition Schema

A resolver definition is a JSON object describing **how** to verify a claim outcome.

### Fields

| Field | Type | Description |
| :--- | :--- | :--- |
| `url` | `string` | The target URL to verify. |
| `method` | `string` | HTTP Method (GET/POST). |
| `path` | `string` | Dot-separated key path in parsed public inputs (example: `data.price`). |
| `predicate` | `string` | Logic to apply (e.g., "contains", "equals", "gte"). |
| `target_value` | `string | int | float | bool` | Value used by the predicate comparison. |

### Canonical Hashing Rule

To ensure all participants agree on resolver logic without storing full JSON on-chain, compute `resolver_hash`.

1.  **Serialize** the JSON object with keys sorted alphabetically and no whitespace separators.
2.  **Encode** as UTF-8 bytes.
3.  **Hash** using SHA-256.

#### Python Implementation

```python
import json
import hashlib

def compute_resolver_hash(definition: dict) -> bytes:
    # 1. Canonical JSON string
    canonical_json = json.dumps(
        definition, 
        sort_keys=True, 
        separators=(',', ':') # Compact: no spaces
    )
    
    # 2. Encode & Hash
    return hashlib.sha256(canonical_json.encode('utf-8')).digest()
```

### Example

Definition:

```json
{
  "url": "https://api.exchange.example/ticker",
  "method": "GET",
  "path": "data.last_price",
  "predicate": "gt",
  "target_value": 3000
}
```

Canonical String:

```text
{"method":"GET","path":"data.last_price","predicate":"gt","target_value":3000,"url":"https://api.exchange.example/ticker"}
```

Hash (Hex):

```text
<sha256 of canonical string>
```

## Notes

- Hashing is over canonical JSON bytes only.
- No network fetch is part of hash calculation.
- The resolver hash must match the on-chain account `resolver_hash` (claim or market legacy path).
