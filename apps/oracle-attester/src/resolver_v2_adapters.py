"""Isolated production adapters for Resolver V2 zkTLS and signed oracles.

No class in this module imports a Solana client or a signer.  Adapters only
produce adapter-neutral ``AcquiredEvidence`` and ``VerificationReport`` values
for the V2 pipeline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Sequence, Tuple

from solders.pubkey import Pubkey
from solders.signature import Signature

from .resolver_v2_pipeline import AcquiredEvidence, PipelineRejected, VerificationReport

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:  # Pipeline's monorepo fallback makes this available in operated bundles.
    from .resolver_v2_pipeline import resolver_v2


SIGNED_ORACLE_DOMAIN = b"PROPHET_SIGNED_ORACLE_V2\x00"
SIGNED_ORACLE_SCHEMA = "prophet.signed-oracle-observation.v2"
SIGNED_ORACLE_VERSION = "2.0.0"
OUTCOMES = frozenset(("YES", "NO", "INVALID"))


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise PipelineRejected(f"{field} must be lowercase bytes32 hex")
    return value


def _uint(value: Any, field: str) -> int:
    try:
        resolver_v2._uint(value, field)
        return int(value)
    except (ValueError, resolver_v2.ResolverV2Error) as exc:
        raise PipelineRejected(str(exc)) from exc


def _descriptor(value: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    try:
        if field == "adapter":
            return resolver_v2._validate_adapter(value)
        return resolver_v2._validate_trust_model(value)
    except resolver_v2.ResolverV2Error as exc:
        raise PipelineRejected(str(exc)) from exc


def _check(check_id: str, passed: bool, expected: str, observed: str) -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "status": "PASS" if passed else "FAIL",
        "expected_commitment": expected,
        "observed_commitment": observed,
        "detail_hash": _hash(f"{check_id}:{expected}:{observed}".encode("ascii")),
    }


def _failure(*, verifier: Mapping[str, Any], code: str, now_ms: str, checks: Sequence[Mapping[str, Any]]) -> VerificationReport:
    return VerificationReport(
        outcome="INVALID", status="REJECTED", confidence="none", verifier=verifier,
        checks=checks, verified_facts={"failure_code": code}, failure_code=code,
        observed_at_ms=now_ms, valid_from_ms=now_ms, valid_until_ms=now_ms, finality=None,
    )


def _source(definition: Mapping[str, Any], expected_type: str) -> Mapping[str, Any]:
    try:
        resolver_v2.validate_resolver_definition(definition)
    except resolver_v2.ResolverV2Error as exc:
        raise PipelineRejected(str(exc)) from exc
    if definition["resolver_type"] != expected_type:
        raise PipelineRejected("wrong_resolver_type")
    return definition["source"]


@dataclass(frozen=True)
class ZkTlsMaterial:
    proof_bytes: bytes
    response_bytes: bytes
    proof_version: str
    acquired_at_ms: str
    source_domain: str
    request_definition_hash: str
    cluster_genesis_hash: str


@dataclass(frozen=True)
class ZkTlsClaims:
    valid: bool
    proof_version: str
    source_domain: str
    request_definition_hash: str
    cluster_genesis_hash: str
    response_hash: str
    reason: str = ""


@dataclass(frozen=True)
class ZkTlsExpectedBinding:
    """Trusted context supplied to a proof backend; it is not evidence data."""
    resolver_id: str
    definition_hash: str
    source_domain: str
    request_definition_hash: str
    cluster_genesis_hash: str
    proof_version: str
    acquired_at_ms: str
    evidence_payload_hash: str


class ZkTlsProofVerifier(Protocol):
    """Implementation-neutral proof verifier contract for independent verifiers."""
    def verify(self, *, proof_bytes: bytes, response_bytes: bytes, expected_binding: ZkTlsExpectedBinding) -> ZkTlsClaims: ...


class ZkTlsAdapter:
    """Canonical zkTLS acquisition and verification; never submits a transaction."""
    def __init__(self, *, adapter_digest: str, verifier_descriptor: Mapping[str, Any], proof_verifier: ZkTlsProofVerifier, clock_ms: Optional[Callable[[], int]] = None):
        self.adapter_digest = _hex(adapter_digest, "adapter_digest")
        self.verifier_descriptor = dict(_descriptor(verifier_descriptor, "adapter"))
        self.proof_verifier = proof_verifier
        self.clock_ms = clock_ms

    @classmethod
    def from_runtime(cls, *, runtime_config: Any, resolver_definition: Mapping[str, Any], verifier_descriptor: Mapping[str, Any], clock_ms: Optional[Callable[[], int]] = None) -> "ZkTlsAdapter":
        """Construct a zkTLS adapter only from explicit, immutable runtime trust."""
        from .zktls_runtime_backend import make_zktls_proof_verifier
        configured = getattr(runtime_config, "zktls", None)
        if configured is None or "zktls" not in getattr(runtime_config, "allowed_adapters", ()):
            raise PipelineRejected("runtime_zktls_not_enabled")
        try:
            resolver_v2.validate_resolver_definition(resolver_definition)
            if resolver_definition["resolver_type"] != "zktls":
                raise PipelineRejected("runtime_zktls_resolver_context_invalid")
            source = resolver_definition["source"]
            cls._validate_source(source)
            if source["proof_version"] not in configured.allowed_proof_versions:
                raise PipelineRejected("runtime_zktls_proof_version_not_allowed")
            adapter_digest = resolver_definition["adapter"]["implementation_digest"]
        except (KeyError, resolver_v2.ResolverV2Error) as exc:
            raise PipelineRejected("runtime_zktls_resolver_context_invalid") from exc
        return cls(adapter_digest=adapter_digest, verifier_descriptor=verifier_descriptor,
                   proof_verifier=make_zktls_proof_verifier(runtime_config), clock_ms=clock_ms)

    @staticmethod
    def _validate_source(source: Mapping[str, Any]) -> None:
        required = {
            "source_domain", "request_definition_hash", "response_selector", "predicate",
            "response_schema", "response_schema_version", "proof_version", "cluster_genesis_hash",
            "max_evidence_age_ms",
        }
        if set(source) != required:
            raise PipelineRejected("zktls_source_schema_mismatch")
        _hex(source["request_definition_hash"], "request_definition_hash")
        _hex(source["cluster_genesis_hash"], "cluster_genesis_hash")
        _uint(source["max_evidence_age_ms"], "max_evidence_age_ms")
        if not isinstance(source["source_domain"], str) or not source["source_domain"]:
            raise PipelineRejected("zktls_source_domain_invalid")
        if not isinstance(source["response_selector"], str) or not source["response_selector"]:
            raise PipelineRejected("zktls_selector_invalid")
        if not isinstance(source["predicate"], Mapping) or not isinstance(source["response_schema"], str) or not isinstance(source["response_schema_version"], str):
            raise PipelineRejected("zktls_response_definition_invalid")

    def acquire(self, definition: Mapping[str, Any], material: ZkTlsMaterial) -> AcquiredEvidence:
        source = _source(definition, "zktls")
        self._validate_source(source)
        if definition["adapter"]["implementation_digest"] != self.adapter_digest:
            raise PipelineRejected("adapter_digest_mismatch")
        if material.source_domain != source["source_domain"] or material.request_definition_hash != source["request_definition_hash"]:
            raise PipelineRejected("zktls_acquisition_binding_mismatch")
        if material.cluster_genesis_hash != source["cluster_genesis_hash"] or material.proof_version != source["proof_version"]:
            raise PipelineRejected("zktls_acquisition_domain_or_version_mismatch")
        _uint(material.acquired_at_ms, "acquired_at_ms")
        payload = {
            "cluster_genesis_hash": material.cluster_genesis_hash, "proof_hex": material.proof_bytes.hex(),
            "proof_version": material.proof_version, "request_definition_hash": material.request_definition_hash,
            "response_hex": material.response_bytes.hex(), "source_domain": material.source_domain,
        }
        raw = resolver_v2.canonical_json_bytes(payload)
        return AcquiredEvidence(
            self.adapter_digest, definition["resolver_id"], material.source_domain, material.acquired_at_ms, raw,
            {"cluster_genesis_hash": material.cluster_genesis_hash, "request_definition_hash": material.request_definition_hash,
             "response_selector": source["response_selector"], "response_schema": source["response_schema"],
             "response_schema_version": source["response_schema_version"], "proof_version": material.proof_version},
            acquisition_id=f"zktls-{_hash(raw)}",
        )

    def verify(self, definition: Mapping[str, Any], evidence: Mapping[str, Any], trust_model: Mapping[str, Any]) -> VerificationReport:
        source = _source(definition, "zktls")
        self._validate_source(source)
        acquired_at = str(evidence.get("acquired_at_ms", "0"))
        now = str(self.clock_ms() if self.clock_ms is not None else acquired_at)
        checks = []
        try:
            _descriptor(trust_model, "trust")
            if definition["trust_model"] != trust_model:
                raise PipelineRejected("trust_model_mismatch")
            if definition["adapter"]["implementation_digest"] != self.adapter_digest:
                raise PipelineRejected("adapter_digest_mismatch")
            definition_hash = resolver_v2.resolver_definition_hash(definition).hex()
            if evidence.get("definition_hash") != definition_hash:
                raise PipelineRejected("resolver_hash_mismatch")
            raw = resolver_v2.parse_canonical_json(bytes.fromhex(str(evidence["payload_hex"])))
            if raw["source_domain"] != source["source_domain"] or raw["request_definition_hash"] != source["request_definition_hash"]:
                raise PipelineRejected("wrong_source_or_request_binding")
            if raw["cluster_genesis_hash"] != source["cluster_genesis_hash"]:
                raise PipelineRejected("wrong_cluster_domain")
            if raw["proof_version"] != source["proof_version"]:
                raise PipelineRejected("unsupported_proof_version")
            if _uint(acquired_at, "acquired_at_ms") + _uint(source["max_evidence_age_ms"], "max_evidence_age_ms") < _uint(now, "now_ms"):
                raise PipelineRejected("stale_evidence")
            expected_binding = ZkTlsExpectedBinding(
                resolver_id=definition["resolver_id"], definition_hash=definition_hash,
                source_domain=source["source_domain"], request_definition_hash=source["request_definition_hash"],
                cluster_genesis_hash=source["cluster_genesis_hash"], proof_version=source["proof_version"],
                acquired_at_ms=acquired_at, evidence_payload_hash=_hash(bytes.fromhex(str(evidence["payload_hex"]))),
            )
            try:
                claims = self.proof_verifier.verify(proof_bytes=bytes.fromhex(raw["proof_hex"]), response_bytes=bytes.fromhex(raw["response_hex"]), expected_binding=expected_binding)
            except Exception as exc:
                raise PipelineRejected("proof_verifier_error") from exc
            if not claims.valid:
                raise PipelineRejected("invalid_proof")
            if (claims.proof_version != raw["proof_version"] or claims.source_domain != raw["source_domain"]
                    or claims.request_definition_hash != raw["request_definition_hash"]
                    or claims.cluster_genesis_hash != raw["cluster_genesis_hash"]
                    or claims.response_hash != _hash(bytes.fromhex(raw["response_hex"]))):
                raise PipelineRejected("proof_claim_binding_mismatch")
            response = json.loads(bytes.fromhex(raw["response_hex"]).decode("utf-8"))
            if not isinstance(response, Mapping) or response.get("schema") != source["response_schema"] or response.get("schema_version") != source["response_schema_version"]:
                raise PipelineRejected("malformed_response_schema")
            selected: Any = response
            for part in source["response_selector"].split("."):
                if not isinstance(selected, Mapping) or part not in selected:
                    raise PipelineRejected("wrong_response_selector")
                selected = selected[part]
            predicate = source["predicate"]
            if not isinstance(predicate.get("allowed_outcomes"), list) or selected not in predicate["allowed_outcomes"] or selected not in OUTCOMES:
                raise PipelineRejected("response_predicate_failed")
            checks.append(_check("proof", True, _hash(bytes.fromhex(raw["proof_hex"])), _hash(bytes.fromhex(raw["proof_hex"]))))
            return VerificationReport(selected, "VERIFIED", "high", checks, self.verifier_descriptor,
                {"response_selector": source["response_selector"], "response_value": selected, "response_schema": source["response_schema"], "response_schema_version": source["response_schema_version"]},
                now, now, str(_uint(now, "now_ms") + _uint(source["max_evidence_age_ms"], "max_evidence_age_ms")), None, {"proof_version": raw["proof_version"]})
        except (PipelineRejected, KeyError, UnicodeDecodeError, json.JSONDecodeError, ValueError, resolver_v2.ResolverV2Error) as exc:
            code = str(exc)
            checks.append(_check("zktls_binding", False, _hash(resolver_v2.canonical_json_bytes(source)), _hash(code.encode("utf-8"))))
            return _failure(verifier=self.verifier_descriptor, code=code, now_ms=str(now), checks=checks)


def signed_oracle_message(payload: Mapping[str, Any]) -> bytes:
    """Unique signed-oracle frame: domain + schema/version lengths + canonical JSON."""
    required = {"schema", "schema_version", "resolver_id", "market", "outcome", "source_timestamp_ms", "sequence", "cluster_genesis_hash", "replay_domain"}
    if set(payload) != required or payload.get("schema") != SIGNED_ORACLE_SCHEMA or payload.get("schema_version") != SIGNED_ORACLE_VERSION:
        raise PipelineRejected("signed_oracle_schema_mismatch")
    if not isinstance(payload["outcome"], str) or not payload["outcome"]:
        raise PipelineRejected("signed_oracle_outcome_invalid")
    for field in ("market", "cluster_genesis_hash", "replay_domain"):
        _hex(payload[field], field)
    _uint(payload["source_timestamp_ms"], "source_timestamp_ms")
    _uint(payload["sequence"], "sequence")
    if not isinstance(payload["resolver_id"], str) or not payload["resolver_id"]:
        raise PipelineRejected("signed_oracle_resolver_invalid")
    body = resolver_v2.canonical_json_bytes(payload)
    schema, version = SIGNED_ORACLE_SCHEMA.encode("ascii"), SIGNED_ORACLE_VERSION.encode("ascii")
    return SIGNED_ORACLE_DOMAIN + len(schema).to_bytes(2, "little") + schema + len(version).to_bytes(2, "little") + version + len(body).to_bytes(4, "little") + body


def parse_signed_oracle_message(message: bytes) -> Dict[str, Any]:
    """Parse the signed frame exactly; alternate frames are never tolerated."""
    offset = len(SIGNED_ORACLE_DOMAIN)
    if not message.startswith(SIGNED_ORACLE_DOMAIN) or len(message) < offset + 8:
        raise PipelineRejected("signed_oracle_message_frame_invalid")
    schema_len = int.from_bytes(message[offset:offset + 2], "little"); offset += 2
    schema = message[offset:offset + schema_len]; offset += schema_len
    version_len = int.from_bytes(message[offset:offset + 2], "little"); offset += 2
    version = message[offset:offset + version_len]; offset += version_len
    body_len = int.from_bytes(message[offset:offset + 4], "little"); offset += 4
    if schema != SIGNED_ORACLE_SCHEMA.encode("ascii") or version != SIGNED_ORACLE_VERSION.encode("ascii") or len(message) != offset + body_len:
        raise PipelineRejected("signed_oracle_message_frame_invalid")
    return resolver_v2.parse_canonical_json(message[offset:])


@dataclass(frozen=True)
class OracleKeyEpoch:
    key_id: str
    public_key: str
    key_set_version: str
    activates_at_ms: str
    retires_at_ms: Optional[str] = None


class OracleKeyring:
    """Explicit, auditable key epochs; overlap requires an explicit key ID."""
    def __init__(self, epochs: Sequence[OracleKeyEpoch]):
        self.epochs = {epoch.key_id: epoch for epoch in epochs}
        if not self.epochs or len(self.epochs) != len(epochs):
            raise PipelineRejected("oracle_keyring_invalid")
        for epoch in epochs:
            Pubkey.from_string(epoch.public_key)
            _uint(epoch.activates_at_ms, "activates_at_ms")
            if epoch.retires_at_ms is not None and _uint(epoch.retires_at_ms, "retires_at_ms") < _uint(epoch.activates_at_ms, "activates_at_ms"):
                raise PipelineRejected("oracle_key_epoch_invalid")

    def resolve(self, key_id: str, at_ms: str, key_set_version: str) -> OracleKeyEpoch:
        epoch = self.epochs.get(key_id)
        if epoch is None or epoch.key_set_version != key_set_version:
            raise PipelineRejected("unknown_oracle_key")
        at = _uint(at_ms, "source_timestamp_ms")
        if at < _uint(epoch.activates_at_ms, "activates_at_ms") or (epoch.retires_at_ms is not None and at >= _uint(epoch.retires_at_ms, "retires_at_ms")):
            raise PipelineRejected("oracle_key_not_active")
        return epoch


class SequenceReplayGuard:
    def __init__(self):
        self._lock, self._seen = Lock(), {}

    def observe(self, *, resolver_id: str, market: str, cluster: str, replay_domain: str, key_id: str, sequence: str, message_hash: str) -> None:
        key = (resolver_id, market, cluster, replay_domain, key_id)
        with self._lock:
            prior = self._seen.get(key)
            current = _uint(sequence, "sequence")
            if prior is not None and current <= prior[0]:
                raise PipelineRejected("duplicate_or_nonmonotonic_sequence")
            self._seen[key] = (current, message_hash)


@dataclass(frozen=True)
class SignedOracleMaterial:
    message: Mapping[str, Any]
    signature: bytes
    key_id: str
    key_set_version: str
    acquired_at_ms: str


class SignedOracleAdapter:
    def __init__(self, *, adapter_digest: str, verifier_descriptor: Mapping[str, Any], keyring: OracleKeyring, replay_guard: Optional[SequenceReplayGuard] = None, clock_ms: Optional[Callable[[], int]] = None):
        self.adapter_digest = _hex(adapter_digest, "adapter_digest")
        self.verifier_descriptor = dict(_descriptor(verifier_descriptor, "adapter"))
        self.keyring, self.replay_guard = keyring, replay_guard or SequenceReplayGuard()
        self.clock_ms = clock_ms

    @classmethod
    def from_runtime(cls, *, runtime_config: Any, registry: Any, resolver_definition: Mapping[str, Any], verifier_descriptor: Mapping[str, Any], message_version: str, replay_guard: Optional[SequenceReplayGuard] = None, clock_ms: Optional[Callable[[], int]] = None) -> "SignedOracleAdapter":
        """Production-only trust wiring; it never accepts raw binding data."""
        from .signed_oracle_runtime_keys import RegistryBackedOracleKeyring
        signed = getattr(runtime_config, "signed_oracle", None)
        if getattr(runtime_config, "mode", None) != "production" or signed is None or "signed-oracle" not in getattr(runtime_config, "allowed_adapters", ()):
            raise PipelineRejected("runtime_signed_oracle_not_enabled")
        if not message_version or message_version != SIGNED_ORACLE_VERSION:
            raise PipelineRejected("runtime_signed_oracle_version_invalid")
        try:
            resolver_v2.validate_resolver_definition(resolver_definition)
            resolver_id = resolver_definition["resolver_id"]
            adapter_digest = resolver_definition["adapter"]["implementation_digest"]
        except (KeyError, resolver_v2.ResolverV2Error) as exc:
            raise PipelineRejected("runtime_resolver_context_invalid") from exc
        if registry is None or resolver_definition.get("resolver_type") != "signed_oracle" or not resolver_id or not signed.key_bindings or registry.fingerprint() != signed.registry_fingerprint:
            raise PipelineRejected("runtime_signed_oracle_trust_invalid")
        keyring = RegistryBackedOracleKeyring(registry, signed.key_bindings, resolver_id=resolver_id, message_version=message_version)
        return cls(adapter_digest=adapter_digest, verifier_descriptor=verifier_descriptor, keyring=keyring, replay_guard=replay_guard, clock_ms=clock_ms)

    @staticmethod
    def _validate_source(source: Mapping[str, Any]) -> None:
        required = {"message_domain", "payload_schema", "payload_schema_version", "market", "cluster_genesis_hash", "replay_domain", "key_set_version", "max_message_age_ms", "outcome_mapping", "require_monotonic_sequence"}
        if set(source) != required:
            raise PipelineRejected("signed_oracle_source_schema_mismatch")
        if source["message_domain"] != "PROPHET_SIGNED_ORACLE_V2" or source["payload_schema"] != SIGNED_ORACLE_SCHEMA or source["payload_schema_version"] != SIGNED_ORACLE_VERSION:
            raise PipelineRejected("signed_oracle_message_definition_invalid")
        for field in ("market", "cluster_genesis_hash", "replay_domain"):
            _hex(source[field], field)
        _uint(source["max_message_age_ms"], "max_message_age_ms")
        if (not isinstance(source["outcome_mapping"], Mapping) or not source["outcome_mapping"]
                or any(not isinstance(key, str) or value not in OUTCOMES for key, value in source["outcome_mapping"].items())
                or not isinstance(source["require_monotonic_sequence"], bool)):
            raise PipelineRejected("signed_oracle_outcome_mapping_invalid")

    def acquire(self, definition: Mapping[str, Any], material: SignedOracleMaterial) -> AcquiredEvidence:
        source = _source(definition, "signed_oracle")
        self._validate_source(source)
        if definition["adapter"]["implementation_digest"] != self.adapter_digest:
            raise PipelineRejected("adapter_digest_mismatch")
        message = signed_oracle_message(material.message)
        if material.message["resolver_id"] != definition["resolver_id"] or material.message["market"] != source["market"] or material.message["cluster_genesis_hash"] != source["cluster_genesis_hash"] or material.message["replay_domain"] != source["replay_domain"]:
            raise PipelineRejected("signed_oracle_acquisition_binding_mismatch")
        payload = {"key_id": material.key_id, "key_set_version": material.key_set_version, "message_hex": message.hex(), "signature_hex": material.signature.hex()}
        raw = resolver_v2.canonical_json_bytes(payload)
        return AcquiredEvidence(self.adapter_digest, definition["resolver_id"], material.key_id, material.acquired_at_ms, raw,
            {"key_set_version": material.key_set_version, "message_hash": _hash(message), "replay_domain": source["replay_domain"]},
            source_time_ms=material.message["source_timestamp_ms"], source_sequence=material.message["sequence"], acquisition_id=f"oracle-{_hash(message)}")

    def verify(self, definition: Mapping[str, Any], evidence: Mapping[str, Any], trust_model: Mapping[str, Any]) -> VerificationReport:
        source = _source(definition, "signed_oracle")
        self._validate_source(source)
        acquired_at = str(evidence.get("acquired_at_ms", "0"))
        now = str(self.clock_ms() if self.clock_ms is not None else acquired_at)
        checks = []
        try:
            _descriptor(trust_model, "trust")
            if definition["trust_model"] != trust_model:
                raise PipelineRejected("trust_model_mismatch")
            if definition["adapter"]["implementation_digest"] != self.adapter_digest:
                raise PipelineRejected("adapter_digest_mismatch")
            if evidence.get("definition_hash") != resolver_v2.resolver_definition_hash(definition).hex():
                raise PipelineRejected("resolver_hash_mismatch")
            raw = resolver_v2.parse_canonical_json(bytes.fromhex(str(evidence["payload_hex"])))
            message = bytes.fromhex(raw["message_hex"])
            payload = parse_signed_oracle_message(message)
            if signed_oracle_message(payload) != message:
                raise PipelineRejected("noncanonical_signed_message")
            for field in ("resolver_id", "market", "cluster_genesis_hash", "replay_domain"):
                expected = definition["resolver_id"] if field == "resolver_id" else source[field]
                if payload[field] != expected:
                    raise PipelineRejected(f"wrong_{field}")
            if payload["outcome"] not in source["outcome_mapping"]:
                raise PipelineRejected("outcome_not_allowed")
            canonical_outcome = source["outcome_mapping"][payload["outcome"]]
            timestamp = _uint(payload["source_timestamp_ms"], "source_timestamp_ms")
            if timestamp > _uint(now, "now_ms") or _uint(now, "acquired_at_ms") - timestamp > _uint(source["max_message_age_ms"], "max_message_age_ms"):
                raise PipelineRejected("stale_signed_observation")
            epoch = self.keyring.resolve(raw["key_id"], payload["source_timestamp_ms"], raw["key_set_version"])
            if raw["key_set_version"] != source["key_set_version"]:
                raise PipelineRejected("wrong_key_set_version")
            signature = Signature.from_bytes(bytes.fromhex(raw["signature_hex"]))
            if not signature.verify(Pubkey.from_string(epoch.public_key), message):
                raise PipelineRejected("invalid_signature")
            if source["require_monotonic_sequence"]:
                self.replay_guard.observe(resolver_id=payload["resolver_id"], market=payload["market"], cluster=payload["cluster_genesis_hash"], replay_domain=payload["replay_domain"], key_id=raw["key_id"], sequence=payload["sequence"], message_hash=_hash(message))
            checks.append(_check("oracle_signature", True, epoch.public_key, epoch.public_key))
            return VerificationReport(canonical_outcome, "VERIFIED", "high", checks, self.verifier_descriptor,
                {"key_id": raw["key_id"], "key_set_version": raw["key_set_version"], "message_hash": _hash(message), "sequence": payload["sequence"]},
                now, payload["source_timestamp_ms"], str(timestamp + _uint(source["max_message_age_ms"], "max_message_age_ms")), None, {"oracle_key_id": raw["key_id"]})
        except (PipelineRejected, KeyError, ValueError, resolver_v2.ResolverV2Error) as exc:
            code = str(exc)
            checks.append(_check("signed_oracle_binding", False, _hash(resolver_v2.canonical_json_bytes(source)), _hash(code.encode("utf-8"))))
            return _failure(verifier=self.verifier_descriptor, code=code, now_ms=now, checks=checks)
