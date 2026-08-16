from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional

class OutcomeEnum(str, Enum):
    YES = "YES"
    NO = "NO"
    INVALID = "INVALID"

class ResolveRequest(BaseModel):
    market: str = Field(..., description="Base58 public key of the market")
    outcome: OutcomeEnum
    proof_bytes_b64: Optional[str] = Field(default="", description="Base64 encoded proof bytes")
    public_inputs_bytes_b64: Optional[str] = Field(default="", description="Base64 encoded public inputs bytes")
    proof_ref: Optional[str] = Field(
        default="",
        description=(
            "Optional proof reference. Local mode accepts "
            "file:<proof-relative-path>:<public-inputs-relative-path> under PROOF_STORE_DIR; "
            "HTTP mode accepts a provider reference."
        ),
    )

class ResolveResponse(BaseModel):
    signature: str
    proof_hash_hex: str
    public_inputs_hash_hex: str
    resolved_ts: int
