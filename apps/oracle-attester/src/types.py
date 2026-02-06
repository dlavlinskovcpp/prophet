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
        description="Optional proof reference for proof fetcher (e.g. file:<proof_path>:<pi_path> or provider ref)",
    )

class ResolveResponse(BaseModel):
    signature: str
    proof_hash_hex: str
    public_inputs_hash_hex: str
    resolved_ts: int
