"""Credential-free coordinator boundary for the two external fixed-role signers.

The coordinator carries only public endpoint/identity metadata and signed,
operation-scoped grant artifacts.  It never loads Vault tokens, private keys,
or an admission-issuer secret, and it performs one identical request per role.
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from solders.pubkey import Pubkey
from solders.signature import Signature

from .signer_admission_grant import AdmissionGrantSignatureV1, AdmissionGrantV1, StrictSignerAuthorizationRequestV1, decode_strict_json


class ExternalSignerBoundaryError(RuntimeError):
    """A fixed-role signer boundary failed closed."""


@dataclass(frozen=True)
class ExternalSignerBinding:
    role: str
    endpoint: str
    signer_id: str
    public_key: str
    key_version: int = 1

    def __post_init__(self) -> None:
        if self.role not in {"A", "B"} or not self.endpoint.startswith(("http://", "https://")):
            raise ExternalSignerBoundaryError("external_signer_binding_invalid")
        if not self.signer_id or isinstance(self.key_version, bool) or not isinstance(self.key_version, int) or self.key_version <= 0:
            raise ExternalSignerBoundaryError("external_signer_binding_invalid")
        try:
            if str(Pubkey.from_string(self.public_key)) != self.public_key:
                raise ValueError
        except Exception as exc:
            raise ExternalSignerBoundaryError("external_signer_binding_invalid") from exc


@dataclass(frozen=True)
class ExternalSignerSignature:
    role: str
    signer_id: str
    public_key: str
    key_version: int
    canonical_message_digest: str
    signature: bytes


def _grant_bytes(path: str | Path) -> bytes:
    try:
        raw = Path(path).read_bytes()
        parsed = decode_strict_json(raw)
        if not isinstance(parsed, dict) or set(parsed) != {"unsigned_grant", "signature_envelope"}:
            raise ValueError
        return raw
    except Exception as exc:
        raise ExternalSignerBoundaryError("external_signer_grant_invalid") from exc


def _response(value: Any, binding: ExternalSignerBinding, message: bytes) -> ExternalSignerSignature:
    required = {"schema", "version", "signer_role", "signer_id", "public_key", "key_version", "scope_id", "settlement_authorization_job_id", "canonical_message_digest", "operation_id", "signature", "state"}
    if not isinstance(value, dict) or set(value) != required or value.get("state") != "SIGNED":
        raise ExternalSignerBoundaryError("external_signer_response_invalid")
    if (value["signer_role"], value["signer_id"], value["public_key"]) != (binding.role, binding.signer_id, binding.public_key):
        raise ExternalSignerBoundaryError("external_signer_identity_mismatch")
    digest = hashlib.sha256(message).hexdigest()
    if value["canonical_message_digest"] != digest:
        raise ExternalSignerBoundaryError("external_signer_message_mismatch")
    try:
        key_version = value["key_version"]
        if isinstance(key_version, bool) or not isinstance(key_version, int) or key_version <= 0 or key_version != binding.key_version:
            raise ValueError
        signature = base64.b64decode(value["signature"], validate=True)
        if len(signature) != 64 or not Signature.from_bytes(signature).verify(Pubkey.from_string(binding.public_key), message):
            raise ValueError
    except Exception as exc:
        raise ExternalSignerBoundaryError("external_signer_signature_invalid") from exc
    return ExternalSignerSignature(binding.role, binding.signer_id, binding.public_key, key_version, digest, signature)


class ExternalFixedRoleSignerPair:
    """Send one canonical authorization request to exactly A and B."""

    def __init__(self, signer_a: ExternalSignerBinding, signer_b: ExternalSignerBinding, *, timeout_seconds: float = 30.0) -> None:
        if signer_a.role != "A" or signer_b.role != "B" or signer_a.endpoint == signer_b.endpoint:
            raise ExternalSignerBoundaryError("external_signer_roles_not_distinct")
        if signer_a.signer_id == signer_b.signer_id or signer_a.public_key == signer_b.public_key:
            raise ExternalSignerBoundaryError("external_signer_identities_not_distinct")
        if timeout_seconds <= 0:
            raise ExternalSignerBoundaryError("external_signer_timeout_invalid")
        self.signer_a, self.signer_b, self.timeout_seconds = signer_a, signer_b, timeout_seconds

    def collect(self, authorization_request: bytes, canonical_message: bytes, *, grant_a: str | Path, grant_b: str | Path) -> tuple[ExternalSignerSignature, ExternalSignerSignature]:
        try:
            StrictSignerAuthorizationRequestV1.from_mapping(decode_strict_json(authorization_request))
        except Exception as exc:
            raise ExternalSignerBoundaryError("external_signer_authorization_request_invalid") from exc
        outputs = [
            self.sign_one("A", authorization_request, canonical_message, grant_path=grant_a),
            self.sign_one("B", authorization_request, canonical_message, grant_path=grant_b),
        ]
        if outputs[0].canonical_message_digest != outputs[1].canonical_message_digest:
            raise ExternalSignerBoundaryError("external_signer_digest_disagreement")
        return outputs[0], outputs[1]

    def sign_one(self, role: str, authorization_request: bytes, canonical_message: bytes, *, grant_path: str | Path) -> ExternalSignerSignature:
        """Make one role-local request; callers decide when its result is durable."""
        binding = self.signer_a if role == "A" else self.signer_b if role == "B" else None
        if binding is None:
            raise ExternalSignerBoundaryError("external_signer_role_invalid")
        try:
            StrictSignerAuthorizationRequestV1.from_mapping(decode_strict_json(authorization_request))
            raw_grant = _grant_bytes(grant_path)
            artifact = decode_strict_json(raw_grant)
            grant = AdmissionGrantV1.from_mapping(artifact["unsigned_grant"]).as_mapping()
            envelope = AdmissionGrantSignatureV1.from_mapping(artifact["signature_envelope"]).values
            if grant["signer_role"] != binding.role or grant["signer_service_id"] != binding.signer_id or envelope["issuer_id"] != grant["issuer_id"] or envelope["key_id"] != grant["key_id"]:
                raise ExternalSignerBoundaryError("external_signer_grant_identity_mismatch")
            encoded_grant = base64.b64encode(raw_grant).decode("ascii")
            req = urllib.request.Request(
                binding.endpoint.rstrip("/") + "/v1/settlement-authorizations",
                data=authorization_request,
                headers={"Content-Type": "application/json", "X-Prophet-Admission-Grant": encoded_grant},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise ExternalSignerBoundaryError("external_signer_rejected")
                body = response.read(65_537)
                if len(body) > 65_536:
                    raise ExternalSignerBoundaryError("external_signer_response_too_large")
                value = json.loads(body.decode("utf-8"))
            return _response(value, binding, canonical_message)
        except ExternalSignerBoundaryError:
            raise
        except (urllib.error.URLError, TimeoutError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalSignerBoundaryError("external_signer_unavailable") from exc
