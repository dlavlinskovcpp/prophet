"""Canonical Resolver V2.0 data formats and hashing.

This module is deliberately off-chain.  It does not alter legacy resolver
hashing or the PROPHET_RESOLVE_V2 settlement message.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence


class ResolverV2Error(ValueError):
    """Raised when a Resolver V2 payload is malformed or non-canonical."""


VERSION = "2.0.0"
SCHEMAS = {
    "adapter": "prophet.adapter-descriptor.v2",
    "trust_model": "prophet.trust-model-descriptor.v2",
    "definition": "prophet.resolver-definition.v2",
    "evidence": "prophet.evidence-envelope.v2",
    "verification": "prophet.verification-result.v2",
    "bundle": "prophet.resolution-bundle.v2",
    "registry": "prophet.resolver-registry-entry.v2",
    "deprecation": "prophet.resolver-deprecation.v2",
}
DOMAINS = {
    "adapter": b"PROPHET_ADAPTER_DESCRIPTOR_V2\x00",
    "trust_model": b"PROPHET_TRUST_MODEL_V2\x00",
    "definition": b"PROPHET_RESOLVER_DEFINITION_V2\x00",
    "evidence": b"PROPHET_EVIDENCE_ENVELOPE_V2\x00",
    "verification": b"PROPHET_VERIFICATION_RESULT_V2\x00",
    "bundle": b"PROPHET_RESOLUTION_BUNDLE_V2\x00",
    "registry": b"PROPHET_RESOLVER_REGISTRY_ENTRY_V2\x00",
    "deprecation": b"PROPHET_RESOLVER_DEPRECATION_V2\x00",
}

_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
_UINT = re.compile(r"^(0|[1-9][0-9]*)$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_ASCII_KEY = re.compile(r"^[a-z][a-z0-9_]*$")
_ID = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")


def _err(message: str) -> None:
    raise ResolverV2Error(message)


def _string(value: Any, field: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str):
        _err(f"{field} must be a string")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        _err(f"{field} must be NFC-normalized")
    if identifier and not _ID.fullmatch(value):
        _err(f"{field} is not a canonical identifier")
    return value


def _uint(value: Any, field: str) -> str:
    value = _string(value, field)
    if not _UINT.fullmatch(value):
        _err(f"{field} must be a canonical unsigned decimal string")
    if int(value) > (2**64 - 1):
        _err(f"{field} exceeds u64")
    return value


def _hex32(value: Any, field: str) -> str:
    value = _string(value, field)
    if not _HEX_32.fullmatch(value):
        _err(f"{field} must be 32 bytes of lowercase hex")
    return value


def _object(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _err(f"{field} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], required: Iterable[str], field: str) -> None:
    required_set = set(required)
    actual = set(value)
    if actual != required_set:
        _err(f"{field} has unexpected or missing fields: expected {sorted(required_set)}")


def _schema(value: Mapping[str, Any], kind: str) -> None:
    if value.get("schema") != SCHEMAS[kind]:
        _err(f"unsupported {kind} schema")
    if value.get("schema_version") != VERSION:
        _err(f"unsupported {kind} schema version")


def _canonical_value(value: Any) -> Any:
    """Validate values allowed in canonical V2 JSON and normalize strings."""
    if value is None or isinstance(value, bool):
        return value
    # bool is an int subclass in Python; reject all numeric JSON values.
    if isinstance(value, (int, float)):
        _err("canonical V2 JSON forbids numeric fields; use canonical decimal strings")
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        if normalized != value:
            _err("canonical V2 JSON strings must be NFC-normalized")
        return value
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str) or not _ASCII_KEY.fullmatch(key):
                _err("canonical V2 object keys must be ASCII snake_case")
            result[key] = _canonical_value(value[key])
        return result
    _err("unsupported canonical V2 JSON value")


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    """Return the unique UTF-8 JSON representation accepted by Resolver V2."""
    canonical = _canonical_value(dict(payload))
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_canonical_json(raw: bytes) -> Dict[str, Any]:
    """Reject valid-but-noncanonical JSON rather than silently canonicalizing it."""
    try:
        decoded = raw.decode("utf-8")
        payload = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResolverV2Error("malformed canonical JSON") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        _err("non-canonical JSON encoding")
    return payload


def _framed_hash(kind: str, payload: Mapping[str, Any]) -> bytes:
    schema = SCHEMAS[kind].encode("ascii")
    version = VERSION.encode("ascii")
    body = canonical_json_bytes(payload)
    if len(schema) > 0xFFFF or len(version) > 0xFFFF or len(body) > 0xFFFFFFFF:
        _err("canonical payload is too large")
    framed = (
        DOMAINS[kind]
        + len(schema).to_bytes(2, "little")
        + schema
        + len(version).to_bytes(2, "little")
        + version
        + len(body).to_bytes(4, "little")
        + body
    )
    return hashlib.sha256(framed).digest()


def _validate_adapter(value: Any) -> Dict[str, Any]:
    value = _object(value, "adapter")
    _exact_keys(value, ("schema", "schema_version", "adapter_id", "adapter_version", "implementation_digest"), "adapter")
    _schema(value, "adapter")
    _string(value["adapter_id"], "adapter.adapter_id", identifier=True)
    if not _VERSION.fullmatch(_string(value["adapter_version"], "adapter.adapter_version")):
        _err("adapter.adapter_version must be semver")
    _hex32(value["implementation_digest"], "adapter.implementation_digest")
    return value


def _validate_trust_model(value: Any) -> Dict[str, Any]:
    value = _object(value, "trust_model")
    _exact_keys(value, ("schema", "schema_version", "trust_model_id", "trust_model_version", "document_hash"), "trust_model")
    _schema(value, "trust_model")
    _string(value["trust_model_id"], "trust_model.trust_model_id", identifier=True)
    if not _VERSION.fullmatch(_string(value["trust_model_version"], "trust_model.trust_model_version")):
        _err("trust_model.trust_model_version must be semver")
    _hex32(value["document_hash"], "trust_model.document_hash")
    return value


def validate_resolver_definition(value: Mapping[str, Any]) -> Dict[str, Any]:
    value = _object(value, "definition")
    _exact_keys(value, (
        "schema", "schema_version", "resolver_id", "resolver_type", "adapter", "trust_model",
        "source", "verification_policy", "evaluation", "timing", "conflict_policy", "fallback_policy",
    ), "definition")
    _schema(value, "definition")
    _string(value["resolver_id"], "definition.resolver_id", identifier=True)
    _string(value["resolver_type"], "definition.resolver_type", identifier=True)
    _validate_adapter(value["adapter"])
    _validate_trust_model(value["trust_model"])
    for field in ("source", "verification_policy", "evaluation", "conflict_policy", "fallback_policy"):
        _object(value[field], f"definition.{field}")
        _canonical_value(value[field])
    timing = _object(value["timing"], "definition.timing")
    _exact_keys(timing, ("not_before_ms", "observation_deadline_ms", "max_evidence_age_ms"), "definition.timing")
    not_before = int(_uint(timing["not_before_ms"], "timing.not_before_ms"))
    deadline = int(_uint(timing["observation_deadline_ms"], "timing.observation_deadline_ms"))
    _uint(timing["max_evidence_age_ms"], "timing.max_evidence_age_ms")
    if deadline < not_before:
        _err("timing.observation_deadline_ms precedes not_before_ms")
    canonical_json_bytes(value)
    return value


def validate_evidence_envelope(value: Mapping[str, Any]) -> Dict[str, Any]:
    value = _object(value, "evidence")
    _exact_keys(value, (
        "schema", "schema_version", "evidence_id", "definition_hash", "acquisition_id",
        "acquired_at_ms", "source_time_ms", "source_sequence", "source_locator",
        "source_commitment", "payload_hex", "payload_hash", "provenance", "transport",
        "collector", "previous_evidence_hash",
    ), "evidence")
    _schema(value, "evidence")
    for field in ("evidence_id", "definition_hash", "source_commitment", "payload_hash"):
        _hex32(value[field], f"evidence.{field}")
    _string(value["acquisition_id"], "evidence.acquisition_id", identifier=True)
    acquired = int(_uint(value["acquired_at_ms"], "evidence.acquired_at_ms"))
    if value["source_time_ms"] is not None and int(_uint(value["source_time_ms"], "evidence.source_time_ms")) > acquired:
        _err("evidence.source_time_ms is after acquired_at_ms")
    if value["source_sequence"] is not None:
        _uint(value["source_sequence"], "evidence.source_sequence")
    if not isinstance(value["payload_hex"], str) or len(value["payload_hex"]) % 2 or not re.fullmatch(r"[0-9a-f]*", value["payload_hex"]):
        _err("evidence.payload_hex must be lowercase even-length hex")
    if hashlib.sha256(bytes.fromhex(value["payload_hex"])).hexdigest() != value["payload_hash"]:
        _err("evidence.payload_hash mismatch")
    for field in ("source_locator", "provenance", "transport", "collector"):
        _object(value[field], f"evidence.{field}")
        _canonical_value(value[field])
    if value["previous_evidence_hash"] is not None:
        _hex32(value["previous_evidence_hash"], "evidence.previous_evidence_hash")
    canonical_json_bytes(value)
    return value


def validate_verification_result(value: Mapping[str, Any], *, now_ms: Optional[int] = None) -> Dict[str, Any]:
    value = _object(value, "verification")
    _exact_keys(value, (
        "schema", "schema_version", "definition_hash", "evidence_hash", "verifier", "result",
        "checks", "verified_facts_hex", "verified_facts_hash", "observed_at_ms", "valid_from_ms",
        "valid_until_ms", "finality",
    ), "verification")
    _schema(value, "verification")
    for field in ("definition_hash", "evidence_hash", "verified_facts_hash"):
        _hex32(value[field], f"verification.{field}")
    _validate_adapter(value["verifier"])
    if value["result"] not in ("VERIFIED", "REJECTED", "INCONCLUSIVE"):
        _err("verification.result is unsupported")
    if not isinstance(value["checks"], list):
        _err("verification.checks must be an array")
    for check in value["checks"]:
        check = _object(check, "verification.check")
        _exact_keys(check, ("check_id", "status", "expected_commitment", "observed_commitment", "detail_hash"), "verification.check")
        _string(check["check_id"], "verification.check.check_id", identifier=True)
        if check["status"] not in ("PASS", "FAIL", "NOT_APPLICABLE"):
            _err("verification.check.status is unsupported")
        _hex32(check["detail_hash"], "verification.check.detail_hash")
        _canonical_value(check["expected_commitment"])
        _canonical_value(check["observed_commitment"])
    if not isinstance(value["verified_facts_hex"], str) or not re.fullmatch(r"[0-9a-f]*", value["verified_facts_hex"]) or len(value["verified_facts_hex"]) % 2:
        _err("verification.verified_facts_hex must be lowercase even-length hex")
    if hashlib.sha256(bytes.fromhex(value["verified_facts_hex"])).hexdigest() != value["verified_facts_hash"]:
        _err("verification.verified_facts_hash mismatch")
    observed = int(_uint(value["observed_at_ms"], "verification.observed_at_ms"))
    valid_from = int(_uint(value["valid_from_ms"], "verification.valid_from_ms"))
    valid_until = int(_uint(value["valid_until_ms"], "verification.valid_until_ms"))
    if not valid_from <= observed <= valid_until:
        _err("verification validity timestamps are inconsistent")
    if now_ms is not None and valid_until < now_ms:
        _err("stale verification result")
    if value["finality"] is not None:
        _object(value["finality"], "verification.finality")
        _canonical_value(value["finality"])
    canonical_json_bytes(value)
    return value


def validate_resolution_bundle(value: Mapping[str, Any], *, now_ms: Optional[int] = None, supported_adapter_versions: Optional[Mapping[str, Sequence[str]]] = None) -> Dict[str, Any]:
    value = _object(value, "bundle")
    _exact_keys(value, (
        "schema", "schema_version", "market", "resolver_definition", "resolver_definition_hash",
        "trust_model", "trust_model_digest", "verifier", "signer_policy", "outcome",
        "observed_at_ms", "valid_until_ms", "cluster_genesis_hash", "settlement_program_id",
        "notary_config", "notary_config_version", "resolution_nonce", "evidence", "verification_results",
    ), "bundle")
    _schema(value, "bundle")
    for field in ("market", "resolver_definition_hash", "trust_model_digest", "cluster_genesis_hash", "settlement_program_id", "notary_config", "resolution_nonce"):
        _hex32(value[field], f"bundle.{field}")
    definition = validate_resolver_definition(value["resolver_definition"])
    if resolver_definition_hash(definition).hex() != value["resolver_definition_hash"]:
        _err("bundle resolver_definition_hash mismatch")
    trust_model = _validate_trust_model(value["trust_model"])
    if trust_model_digest(trust_model).hex() != value["trust_model_digest"]:
        _err("bundle trust_model_digest mismatch")
    if definition["trust_model"] != trust_model:
        _err("bundle trust model differs from resolver definition")
    verifier = _validate_adapter(value["verifier"])
    if supported_adapter_versions is not None and verifier["adapter_version"] not in supported_adapter_versions.get(verifier["adapter_id"], ()):
        _err("unsupported verifier adapter version")
    signer_policy = _object(value["signer_policy"], "bundle.signer_policy")
    _exact_keys(signer_policy, ("policy_id", "policy_version", "threshold", "allowed_adapter_digest"), "bundle.signer_policy")
    _string(signer_policy["policy_id"], "signer_policy.policy_id", identifier=True)
    if not _VERSION.fullmatch(_string(signer_policy["policy_version"], "signer_policy.policy_version")):
        _err("signer_policy.policy_version must be semver")
    if int(_uint(signer_policy["threshold"], "signer_policy.threshold")) == 0:
        _err("signer_policy.threshold must be positive")
    if signer_policy["allowed_adapter_digest"] != verifier["implementation_digest"]:
        _err("signer policy does not allow verifier implementation")
    if value["outcome"] not in ("YES", "NO", "INVALID"):
        _err("bundle outcome is unsupported")
    observed = int(_uint(value["observed_at_ms"], "bundle.observed_at_ms"))
    valid_until = int(_uint(value["valid_until_ms"], "bundle.valid_until_ms"))
    if observed > valid_until or (now_ms is not None and valid_until < now_ms):
        _err("bundle is stale or has inconsistent timestamps")
    _uint(value["notary_config_version"], "bundle.notary_config_version")
    if not isinstance(value["evidence"], list) or not isinstance(value["verification_results"], list):
        _err("bundle evidence and verification_results must be arrays")
    evidence_ids = set()
    evidence_hashes = set()
    last_id = ""
    for evidence in value["evidence"]:
        evidence = validate_evidence_envelope(evidence)
        if evidence["definition_hash"] != value["resolver_definition_hash"]:
            _err("inconsistent resolver binding in evidence")
        if evidence["evidence_id"] in evidence_ids or evidence["evidence_id"] <= last_id:
            _err("duplicate or non-canonically ordered evidence IDs")
        evidence_ids.add(evidence["evidence_id"])
        last_id = evidence["evidence_id"]
        evidence_hashes.add(evidence_hash(evidence).hex())
        if int(evidence["acquired_at_ms"]) > observed:
            _err("bundle observed time precedes evidence")
    if not evidence_ids:
        _err("bundle must contain evidence")
    last_hash = ""
    for result in value["verification_results"]:
        result = validate_verification_result(result, now_ms=now_ms)
        if result["definition_hash"] != value["resolver_definition_hash"] or result["evidence_hash"] not in evidence_hashes:
            _err("inconsistent verification binding")
        result_hash = verification_result_hash(result).hex()
        if result_hash <= last_hash:
            _err("verification results must be sorted by result hash")
        last_hash = result_hash
        if int(result["observed_at_ms"]) > observed or int(result["valid_until_ms"]) < valid_until:
            _err("conflicting bundle and verification timestamps")
    if not value["verification_results"]:
        _err("bundle must contain verification results")
    canonical_json_bytes(value)
    return value


def adapter_digest(value: Mapping[str, Any]) -> bytes:
    return _framed_hash("adapter", _validate_adapter(value))


def trust_model_digest(value: Mapping[str, Any]) -> bytes:
    return _framed_hash("trust_model", _validate_trust_model(value))


def resolver_definition_hash(value: Mapping[str, Any]) -> bytes:
    return _framed_hash("definition", validate_resolver_definition(value))


def evidence_hash(value: Mapping[str, Any]) -> bytes:
    return _framed_hash("evidence", validate_evidence_envelope(value))


def verification_result_hash(value: Mapping[str, Any]) -> bytes:
    return _framed_hash("verification", validate_verification_result(value))


def resolution_bundle_hash(value: Mapping[str, Any]) -> bytes:
    return _framed_hash("bundle", validate_resolution_bundle(value))


@dataclass(frozen=True)
class RegistryEntryV2:
    resolver_id: str
    resolver_definition_hash: str
    adapter_digest: str
    trust_model_digest: str
    schema_version: str
    created_at_ms: str
    deprecated_at_ms: Optional[str] = None
    deprecation_reason: Optional[str] = None
    replacement_resolver_id: Optional[str] = None

    def payload(self) -> Dict[str, Any]:
        payload = {
            "schema": SCHEMAS["registry"], "schema_version": self.schema_version,
            "resolver_id": self.resolver_id, "resolver_definition_hash": self.resolver_definition_hash,
            "adapter_digest": self.adapter_digest, "trust_model_digest": self.trust_model_digest,
            "created_at_ms": self.created_at_ms, "deprecated_at_ms": self.deprecated_at_ms,
            "deprecation_reason": self.deprecation_reason, "replacement_resolver_id": self.replacement_resolver_id,
        }
        _validate_registry_entry(payload)
        return payload

    def digest(self) -> bytes:
        return _framed_hash("registry", self.payload())


def _validate_registry_entry(value: Mapping[str, Any]) -> None:
    _exact_keys(value, (
        "schema", "schema_version", "resolver_id", "resolver_definition_hash", "adapter_digest",
        "trust_model_digest", "created_at_ms", "deprecated_at_ms", "deprecation_reason", "replacement_resolver_id",
    ), "registry entry")
    _schema(value, "registry")
    _string(value["resolver_id"], "registry.resolver_id", identifier=True)
    for field in ("resolver_definition_hash", "adapter_digest", "trust_model_digest"):
        _hex32(value[field], f"registry.{field}")
    _uint(value["created_at_ms"], "registry.created_at_ms")
    if value["deprecated_at_ms"] is not None:
        _uint(value["deprecated_at_ms"], "registry.deprecated_at_ms")
        _string(value["deprecation_reason"], "registry.deprecation_reason")
    elif value["deprecation_reason"] is not None or value["replacement_resolver_id"] is not None:
        _err("registry deprecation metadata requires deprecated_at_ms")
    if value["replacement_resolver_id"] is not None:
        _string(value["replacement_resolver_id"], "registry.replacement_resolver_id", identifier=True)


class ImmutableResolverRegistryV2:
    """In-memory immutable-entry registry model; persistence/governance is out of scope."""

    def __init__(self) -> None:
        self._entries: Dict[str, RegistryEntryV2] = {}
        self._deprecations: Dict[str, Dict[str, Any]] = {}

    def create(self, entry: RegistryEntryV2) -> RegistryEntryV2:
        entry.payload()
        if entry.resolver_id in self._entries:
            _err("resolver ID already exists; registry entries are immutable")
        if any(existing.resolver_definition_hash == entry.resolver_definition_hash for existing in self._entries.values()):
            _err("resolver definition hash is already registered")
        self._entries[entry.resolver_id] = entry
        return entry

    def deprecate(self, resolver_id: str, deprecated_at_ms: str, reason: str, replacement_resolver_id: Optional[str] = None) -> Dict[str, Any]:
        if resolver_id not in self._entries or resolver_id in self._deprecations:
            _err("unknown or already deprecated resolver")
        _uint(deprecated_at_ms, "deprecation.deprecated_at_ms")
        _string(reason, "deprecation.reason")
        if replacement_resolver_id is not None:
            _string(replacement_resolver_id, "deprecation.replacement_resolver_id", identifier=True)
        record = {
            "schema": SCHEMAS["deprecation"], "schema_version": VERSION,
            "resolver_id": resolver_id, "deprecated_at_ms": deprecated_at_ms,
            "reason": reason, "replacement_resolver_id": replacement_resolver_id,
            "entry_digest": self._entries[resolver_id].digest().hex(),
        }
        _canonical_value(record)
        self._deprecations[resolver_id] = record
        return record

    def get(self, resolver_id: str) -> RegistryEntryV2:
        return self._entries[resolver_id]

    def deprecation(self, resolver_id: str) -> Optional[Dict[str, Any]]:
        return self._deprecations.get(resolver_id)
