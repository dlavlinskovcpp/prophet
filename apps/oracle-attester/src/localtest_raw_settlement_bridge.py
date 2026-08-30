"""Immutable public bridge from independent A/B signatures to settlement wire."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from solders.pubkey import Pubkey
from solders.signature import Signature


class LocaltestRawSettlementBridgeError(ValueError):
    pass


def _key(value: Any, name: str) -> str:
    try:
        if not isinstance(value, str) or str(Pubkey.from_string(value)) != value:
            raise ValueError
    except Exception as exc:
        raise LocaltestRawSettlementBridgeError(f"{name}_invalid") from exc
    return value


def _sig(value: Any, name: str) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        try:
            raw = base64.b64decode(value.encode("ascii"), validate=True)
        except Exception as exc:
            raise LocaltestRawSettlementBridgeError(f"{name}_invalid") from exc
    else:
        raise LocaltestRawSettlementBridgeError(f"{name}_invalid")
    if len(raw) != 64:
        raise LocaltestRawSettlementBridgeError(f"{name}_invalid")
    return raw


@dataclass(frozen=True)
class LocaltestRawSettlementSignaturesV1:
    canonical_message: bytes
    canonical_message_sha256: str
    signer_a_id: str
    signer_a_public_key: str
    signer_a_key_version: int
    signer_a_signature: bytes
    signer_b_id: str
    signer_b_public_key: str
    signer_b_key_version: int
    signer_b_signature: bytes
    schema: str = "PROPHET_LOCALTEST_RAW_SETTLEMENT_SIGNATURES_V1"
    version: int = 1

    def __post_init__(self) -> None:
        if self.schema != "PROPHET_LOCALTEST_RAW_SETTLEMENT_SIGNATURES_V1" or self.version != 1:
            raise LocaltestRawSettlementBridgeError("settlement_bridge_schema_invalid")
        if not isinstance(self.canonical_message, bytes) or len(self.canonical_message) != 235 or not self.canonical_message.startswith(b"PROPHET_RESOLVE_V2"):
            raise LocaltestRawSettlementBridgeError("settlement_bridge_message_invalid")
        if hashlib.sha256(self.canonical_message).hexdigest() != self.canonical_message_sha256:
            raise LocaltestRawSettlementBridgeError("settlement_bridge_digest_invalid")
        for value, name in ((self.signer_a_id, "signer_a_id"), (self.signer_b_id, "signer_b_id")):
            if not isinstance(value, str) or not value:
                raise LocaltestRawSettlementBridgeError(f"{name}_invalid")
        _key(self.signer_a_public_key, "signer_a_public_key")
        _key(self.signer_b_public_key, "signer_b_public_key")
        if self.signer_a_public_key == self.signer_b_public_key or self.signer_a_id == self.signer_b_id:
            raise LocaltestRawSettlementBridgeError("settlement_bridge_identity_collision")
        for value, name in ((self.signer_a_key_version, "signer_a_key_version"), (self.signer_b_key_version, "signer_b_key_version")):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise LocaltestRawSettlementBridgeError(f"{name}_invalid")
        if not isinstance(self.signer_a_signature, bytes) or len(self.signer_a_signature) != 64 or not isinstance(self.signer_b_signature, bytes) or len(self.signer_b_signature) != 64:
            raise LocaltestRawSettlementBridgeError("settlement_bridge_signature_invalid")

    @classmethod
    def from_mapping(cls, value: Any) -> "LocaltestRawSettlementSignaturesV1":
        fields = {"schema", "version", "canonical_message", "canonical_message_sha256", "signer_a_id", "signer_a_public_key", "signer_a_key_version", "signer_a_signature", "signer_b_id", "signer_b_public_key", "signer_b_key_version", "signer_b_signature"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise LocaltestRawSettlementBridgeError("settlement_bridge_shape_invalid")
        try:
            message = base64.b64decode(value["canonical_message"].encode("ascii"), validate=True)
        except Exception as exc:
            raise LocaltestRawSettlementBridgeError("settlement_bridge_message_invalid") from exc
        return cls(message, value["canonical_message_sha256"], value["signer_a_id"], value["signer_a_public_key"], value["signer_a_key_version"], _sig(value["signer_a_signature"], "signer_a_signature"), value["signer_b_id"], value["signer_b_public_key"], value["signer_b_key_version"], _sig(value["signer_b_signature"], "signer_b_signature"), value["schema"], value["version"])

    def validate(self, *, expected_message: bytes, signer_a_id: str, signer_a_public_key: str, signer_a_key_version: int, signer_b_id: str, signer_b_public_key: str, signer_b_key_version: int) -> None:
        if self.canonical_message != expected_message or self.signer_a_id != signer_a_id or self.signer_a_public_key != signer_a_public_key or self.signer_a_key_version != signer_a_key_version or self.signer_b_id != signer_b_id or self.signer_b_public_key != signer_b_public_key or self.signer_b_key_version != signer_b_key_version:
            raise LocaltestRawSettlementBridgeError("settlement_bridge_binding_mismatch")
        try:
            if not Signature.from_bytes(self.signer_a_signature).verify(Pubkey.from_string(self.signer_a_public_key), self.canonical_message):
                raise ValueError
            if not Signature.from_bytes(self.signer_b_signature).verify(Pubkey.from_string(self.signer_b_public_key), self.canonical_message):
                raise ValueError
        except Exception as exc:
            raise LocaltestRawSettlementBridgeError("settlement_bridge_signature_invalid") from exc

    def as_mapping(self) -> dict[str, Any]:
        return {"schema": self.schema, "version": self.version, "canonical_message": base64.b64encode(self.canonical_message).decode("ascii"), "canonical_message_sha256": self.canonical_message_sha256, "signer_a_id": self.signer_a_id, "signer_a_public_key": self.signer_a_public_key, "signer_a_key_version": self.signer_a_key_version, "signer_a_signature": base64.b64encode(self.signer_a_signature).decode("ascii"), "signer_b_id": self.signer_b_id, "signer_b_public_key": self.signer_b_public_key, "signer_b_key_version": self.signer_b_key_version, "signer_b_signature": base64.b64encode(self.signer_b_signature).decode("ascii")}


def build_localtest_raw_settlement_signatures(*, canonical_message: bytes, signer_a_id: str, signer_a_public_key: str, signer_a_key_version: int, signer_a_signature: bytes, signer_b_id: str, signer_b_public_key: str, signer_b_key_version: int, signer_b_signature: bytes) -> LocaltestRawSettlementSignaturesV1:
    return LocaltestRawSettlementSignaturesV1(canonical_message, hashlib.sha256(canonical_message).hexdigest(), signer_a_id, signer_a_public_key, signer_a_key_version, signer_a_signature, signer_b_id, signer_b_public_key, signer_b_key_version, signer_b_signature)
