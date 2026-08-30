#!/usr/bin/env python3
"""Operated-devnet acceptance controller for external fixed-role signers.

This process has no signing, Vault, issuer, or signer-service lifecycle
authority. It presents independently issued, one-shot G1 grants to two
already-running fixed-role services and validates their returned signatures.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parent.parent
ATTESTER_DIR = ROOT / "apps" / "oracle-attester"
if str(ATTESTER_DIR) not in sys.path:
    sys.path.insert(0, str(ATTESTER_DIR))

from solders.pubkey import Pubkey
from solders.signature import Signature
from src.signer_admission_grant import (  # noqa: E402
    AdmissionGrantSignatureV1,
    AdmissionGrantV1,
    StrictSignerAuthorizationRequestV1,
    decode_strict_json,
)


class DevnetSmokeError(RuntimeError):
    pass


_FORBIDDEN_CONTROLLER_ENV = frozenset((
    "SIGNER_A_VAULT_TOKEN", "SIGNER_B_VAULT_TOKEN",
    "SIGNER_A_PRIVATE_KEY", "SIGNER_B_PRIVATE_KEY",
    "ISSUER_A_PRIVATE_KEY", "ISSUER_B_PRIVATE_KEY",
    "SIGNER_A_ADMISSION_TOKEN", "SIGNER_B_ADMISSION_TOKEN",
    "ADMISSION_TOKEN", "REMOTE_SIGNER_API_KEY",
))
_RESPONSE_FIELDS = frozenset((
    "schema", "version", "signer_role", "signer_id", "public_key", "key_version",
    "scope_id", "settlement_authorization_job_id", "canonical_message_digest",
    "operation_id", "signature", "state",
))


@dataclass(frozen=True)
class ExternalSigner:
    role: str
    endpoint: str
    signer_id: str
    public_key: str
    grant: Mapping[str, Any]


def _strict_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise DevnetSmokeError(f"{name} is invalid")
    return value


def _endpoint(value: str, name: str) -> str:
    value = _strict_text(value, name)
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise DevnetSmokeError(f"{name} must be an absolute HTTP(S) endpoint without credentials")
    return value.rstrip("/")


def _public_key(value: str, name: str) -> str:
    try:
        parsed = str(Pubkey.from_string(_strict_text(value, name)))
    except Exception as exc:
        raise DevnetSmokeError(f"{name} is invalid") from exc
    if parsed != value:
        raise DevnetSmokeError(f"{name} is non-canonical")
    return value


def _acceptance_run_id(value: str | None) -> str:
    candidate = secrets.token_hex(16) if value is None else value
    if not isinstance(candidate, str) or len(candidate) != 32 or any(char not in "0123456789abcdef" for char in candidate):
        raise DevnetSmokeError("acceptance_run_id must be 32 lowercase hex characters")
    return candidate


def _load_json_object(path: str, label: str) -> tuple[dict[str, Any], bytes]:
    source = Path(path).expanduser().resolve()
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise DevnetSmokeError(f"{label} cannot be read: {source}") from exc
    try:
        parsed = decode_strict_json(raw)
    except Exception as exc:
        raise DevnetSmokeError(f"{label} is not strict JSON") from exc
    if not isinstance(parsed, dict):
        raise DevnetSmokeError(f"{label} must be a JSON object")
    return parsed, raw


def _load_grant(path: str, *, role: str, signer_id: str, run_id: str) -> dict[str, Any]:
    artifact, _ = _load_json_object(path, f"signer {role} admission grant")
    if set(artifact) != {"unsigned_grant", "signature_envelope"}:
        raise DevnetSmokeError(f"signer {role} admission grant transport is invalid")
    try:
        grant = AdmissionGrantV1.from_mapping(artifact["unsigned_grant"]).as_mapping()
        envelope = AdmissionGrantSignatureV1.from_mapping(artifact["signature_envelope"]).values
    except Exception as exc:
        raise DevnetSmokeError(f"signer {role} admission grant is invalid") from exc
    if (grant["signer_role"], grant["signer_service_id"], grant["acceptance_run_id"]) != (role, signer_id, run_id):
        raise DevnetSmokeError(f"signer {role} admission grant has the wrong fixed context")
    if envelope["issuer_id"] != grant["issuer_id"] or envelope["key_id"] != grant["key_id"]:
        raise DevnetSmokeError(f"signer {role} admission grant envelope is unbound")
    return artifact


def _assert_controller_secret_boundary(environ: Mapping[str, str]) -> None:
    present = sorted(name for name in _FORBIDDEN_CONTROLLER_ENV if environ.get(name, ""))
    if present:
        raise DevnetSmokeError("controller environment contains forbidden signer or issuer credentials: " + ", ".join(present))


def _post_signer(endpoint: str, request_bytes: bytes, grant: Mapping[str, Any]) -> tuple[int, str]:
    header = base64.b64encode(json.dumps(grant, separators=(",", ":")).encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        endpoint + "/v1/settlement-authorizations", data=request_bytes,
        headers={"Content-Type": "application/json", "X-Prophet-Admission-Grant": header}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except Exception as exc:
        raise DevnetSmokeError(f"external signer request failed: {endpoint}") from exc


def _validate_response(response: Any, signer: ExternalSigner, message: bytes) -> dict[str, Any]:
    if not isinstance(response, dict) or set(response) != _RESPONSE_FIELDS:
        raise DevnetSmokeError(f"signer {signer.role} response shape is invalid")
    if response.get("schema") != "PROPHET_SIGNER_SIGNATURE_V1" or response.get("version") != "1" or response.get("state") != "SIGNED":
        raise DevnetSmokeError(f"signer {signer.role} response is not a durable signature")
    if (response.get("signer_role"), response.get("signer_id"), response.get("public_key")) != (signer.role, signer.signer_id, signer.public_key):
        raise DevnetSmokeError(f"signer {signer.role} response identity mismatch")
    if response.get("canonical_message_digest") != hashlib.sha256(message).hexdigest():
        raise DevnetSmokeError(f"signer {signer.role} response message mismatch")
    try:
        signature = base64.b64decode(response["signature"], validate=True)
        valid = Signature.from_bytes(signature).verify(Pubkey.from_string(signer.public_key), message)
    except Exception as exc:
        raise DevnetSmokeError(f"signer {signer.role} response signature is invalid") from exc
    if not valid:
        raise DevnetSmokeError(f"signer {signer.role} response signature is invalid")
    return response


def run_acceptance_flow(
    *, request_bytes: bytes, canonical_message: bytes, signer_a: ExternalSigner, signer_b: ExternalSigner,
    post: Callable[[str, bytes, Mapping[str, Any]], tuple[int, str]] = _post_signer,
) -> dict[str, Any]:
    """Submit identical bytes once to each external signer; never resend grants."""
    if signer_a.role != "A" or signer_b.role != "B" or signer_a.endpoint == signer_b.endpoint or signer_a.public_key == signer_b.public_key:
        raise DevnetSmokeError("external signer topology is not role-distinct")
    if not isinstance(canonical_message, bytes) or len(canonical_message) != 235 or not canonical_message.startswith(b"PROPHET_RESOLVE_V2"):
        raise DevnetSmokeError("canonical settlement message is invalid")
    try:
        StrictSignerAuthorizationRequestV1.from_mapping(decode_strict_json(request_bytes))
    except Exception as exc:
        raise DevnetSmokeError("authorization request is invalid") from exc
    responses: list[dict[str, Any]] = []
    for signer in (signer_a, signer_b):
        status, raw = post(signer.endpoint, request_bytes, signer.grant)
        if status != 200:
            raise DevnetSmokeError(f"signer {signer.role} rejected admission or signing; no 2-of-2 bundle")
        try:
            responses.append(_validate_response(json.loads(raw), signer, canonical_message))
        except json.JSONDecodeError as exc:
            raise DevnetSmokeError(f"signer {signer.role} returned malformed JSON") from exc
    return {"schema": "PROPHET_EXTERNAL_SIGNER_BUNDLE_V1", "signatures": responses}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate two external fixed-role signer responses; this controller never launches signers.")
    parser.add_argument("--authorization-request-file", required=True)
    parser.add_argument("--canonical-message-file", required=True)
    parser.add_argument("--signer-a-endpoint", required=True)
    parser.add_argument("--signer-b-endpoint", required=True)
    parser.add_argument("--signer-a-id", required=True)
    parser.add_argument("--signer-b-id", required=True)
    parser.add_argument("--signer-a-public-key", required=True)
    parser.add_argument("--signer-b-public-key", required=True)
    parser.add_argument("--signer-a-grant-file", required=True)
    parser.add_argument("--signer-b-grant-file", required=True)
    parser.add_argument("--acceptance-run-id", default=None, help="Optional externally coordinated 128-bit run ID; otherwise generated locally.")
    args = parser.parse_args()
    _assert_controller_secret_boundary(os.environ)
    run_id = _acceptance_run_id(args.acceptance_run_id)
    request, request_bytes = _load_json_object(args.authorization_request_file, "authorization request")
    try:
        StrictSignerAuthorizationRequestV1.from_mapping(request)
    except Exception as exc:
        raise SystemExit("authorization request is invalid") from exc
    try:
        message = Path(args.canonical_message_file).expanduser().resolve().read_bytes()
    except OSError as exc:
        raise SystemExit("canonical message cannot be read") from exc
    a = ExternalSigner("A", _endpoint(args.signer_a_endpoint, "signer A endpoint"), _strict_text(args.signer_a_id, "signer A id"), _public_key(args.signer_a_public_key, "signer A public key"), _load_grant(args.signer_a_grant_file, role="A", signer_id=args.signer_a_id, run_id=run_id))
    b = ExternalSigner("B", _endpoint(args.signer_b_endpoint, "signer B endpoint"), _strict_text(args.signer_b_id, "signer B id"), _public_key(args.signer_b_public_key, "signer B public key"), _load_grant(args.signer_b_grant_file, role="B", signer_id=args.signer_b_id, run_id=run_id))
    bundle = run_acceptance_flow(request_bytes=request_bytes, canonical_message=message, signer_a=a, signer_b=b)
    print(json.dumps({"acceptance_run_id": run_id, **bundle}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
