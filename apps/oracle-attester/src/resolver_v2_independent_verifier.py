"""Independent zkTLS verifier implementation for Resolver V2.

This is intentionally not a wrapper around ``ZkTlsAdapter.verify``. It has its
own parsing, binding checks, and response traversal; it shares only V2 schemas,
hash functions, constants, and the implementation-neutral proof-checker ABI.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Protocol

from .resolver_v2_pipeline import PipelineRejected, VerificationReport

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _check(name: str, okay: bool, expected: str, actual: str) -> Dict[str, Any]:
    return {"check_id": name, "status": "PASS" if okay else "FAIL", "expected_commitment": expected, "observed_commitment": actual, "detail_hash": _digest(f"{name}:{expected}:{actual}".encode())}


@dataclass(frozen=True)
class IndependentProofClaims:
    accepted: bool
    version: str
    domain: str
    request_hash: str
    cluster_hash: str
    response_digest: str


class IndependentProofChecker(Protocol):
    """A separately audited proof-validation implementation boundary."""
    def validate(self, encoded_proof: bytes, response_bytes: bytes) -> IndependentProofClaims: ...


class IndependentZkTlsVerifier:
    """Second verifier path with stable, policy-addressable implementation identity."""
    def __init__(self, descriptor: Mapping[str, Any], checker: IndependentProofChecker, *, clock_ms: Optional[Callable[[], int]] = None):
        resolver_v2._validate_adapter(descriptor)
        self.descriptor, self.checker, self.clock_ms = dict(descriptor), checker, clock_ms

    def _reject(self, code: str, now: str, checks: list[Mapping[str, Any]]) -> VerificationReport:
        checks.append(_check("independent_verification", False, _digest(code.encode()), _digest(code.encode())))
        return VerificationReport("INVALID", "REJECTED", "none", checks, self.descriptor, {"failure_code": code}, now, now, now, code, None)

    def verify(self, definition: Mapping[str, Any], evidence: Mapping[str, Any], trust_model: Mapping[str, Any]) -> VerificationReport:
        now = str(self.clock_ms() if self.clock_ms is not None else evidence.get("acquired_at_ms", "0"))
        checks: list[Mapping[str, Any]] = []
        try:
            resolver_v2.validate_resolver_definition(definition)
            resolver_v2._validate_trust_model(trust_model)
            if definition["resolver_type"] != "zktls" or definition["trust_model"] != trust_model:
                raise PipelineRejected("independent_trust_or_type_mismatch")
            source = definition["source"]
            expected = {"source_domain", "request_definition_hash", "response_selector", "predicate", "response_schema", "response_schema_version", "proof_version", "cluster_genesis_hash", "max_evidence_age_ms"}
            if set(source) != expected or definition["adapter"]["implementation_digest"] == "":
                raise PipelineRejected("independent_definition_schema_mismatch")
            if evidence.get("definition_hash") != resolver_v2.resolver_definition_hash(definition).hex():
                raise PipelineRejected("independent_resolver_hash_mismatch")
            acquired = int(str(evidence["acquired_at_ms"]))
            if int(now) - acquired > int(str(source["max_evidence_age_ms"])):
                raise PipelineRejected("independent_stale_evidence")
            encoded = bytes.fromhex(str(evidence["payload_hex"]))
            record = resolver_v2.parse_canonical_json(encoded)
            required_payload = {"cluster_genesis_hash", "proof_hex", "proof_version", "request_definition_hash", "response_hex", "source_domain"}
            if set(record) != required_payload:
                raise PipelineRejected("independent_evidence_format_mismatch")
            for field, source_field in (("source_domain", "source_domain"), ("request_definition_hash", "request_definition_hash"), ("cluster_genesis_hash", "cluster_genesis_hash"), ("proof_version", "proof_version")):
                if record[field] != source[source_field]:
                    raise PipelineRejected(f"independent_{field}_mismatch")
            response = bytes.fromhex(record["response_hex"])
            claims = self.checker.validate(bytes.fromhex(record["proof_hex"]), response)
            if not claims.accepted:
                raise PipelineRejected("independent_invalid_proof")
            if (claims.version, claims.domain, claims.request_hash, claims.cluster_hash, claims.response_digest) != (record["proof_version"], record["source_domain"], record["request_definition_hash"], record["cluster_genesis_hash"], _digest(response)):
                raise PipelineRejected("independent_proof_claim_mismatch")
            parsed = json.loads(response.decode("utf-8"))
            if not isinstance(parsed, dict) or parsed.get("schema") != source["response_schema"] or parsed.get("schema_version") != source["response_schema_version"]:
                raise PipelineRejected("independent_response_schema_mismatch")
            selected: Any = parsed
            for token in str(source["response_selector"]).split("."):
                if not isinstance(selected, dict):
                    raise PipelineRejected("independent_selector_mismatch")
                selected = selected.get(token)
            allowed = source["predicate"].get("allowed_outcomes") if isinstance(source["predicate"], dict) else None
            if selected not in ("YES", "NO", "INVALID") or not isinstance(allowed, list) or selected not in allowed:
                raise PipelineRejected("independent_predicate_mismatch")
            checks.append(_check("independent_proof", True, _digest(response), claims.response_digest))
            return VerificationReport(selected, "VERIFIED", "high", checks, self.descriptor, {"outcome": selected, "response_digest": claims.response_digest, "verifier_path": "independent"}, now, now, str(int(now) + int(str(source["max_evidence_age_ms"]))), None, {"proof_version": claims.version})
        except (PipelineRejected, ValueError, KeyError, UnicodeDecodeError, json.JSONDecodeError, resolver_v2.ResolverV2Error) as exc:
            return self._reject(str(exc), now, checks)


class IndependentOracleVerifier:
    """Second implementation for canonical Pyth/Chainlink evidence.

    This deliberately has independent parsing and fixed-point comparison code;
    it imports neither the primary oracle adapters nor their predicate helper.
    """
    _int = re.compile(r"-?(0|[1-9][0-9]*)$")
    _max = (1 << 127) - 1

    def __init__(self, descriptor: Mapping[str, Any], *, clock_ms: Optional[Callable[[], int]] = None):
        resolver_v2._validate_adapter(descriptor)
        self.descriptor, self.clock_ms = dict(descriptor), clock_ms

    @classmethod
    def _number(cls, value: Any, name: str) -> int:
        if not isinstance(value, str) or not cls._int.fullmatch(value):
            raise PipelineRejected(f"independent_{name}_invalid")
        value = int(value)
        if abs(value) > cls._max: raise PipelineRejected(f"independent_{name}_overflow")
        return value

    @classmethod
    def _outcome(cls, value: str, exponent: str, predicate: Mapping[str, Any]) -> str:
        if set(predicate) != {"operator", "threshold_value", "threshold_exponent", "outcome_if_true", "outcome_if_false"} or predicate.get("operator") not in {"<", "<=", ">", ">=", "=="}:
            raise PipelineRejected("independent_predicate_invalid")
        left, left_e = cls._number(value, "value"), cls._number(exponent, "exponent")
        right, right_e = cls._number(predicate["threshold_value"], "threshold"), cls._number(predicate["threshold_exponent"], "threshold_exponent")
        if not (-255 <= left_e <= 255 and -255 <= right_e <= 255): raise PipelineRejected("independent_exponent_range")
        common = min(left_e, right_e)
        def adjusted(v: int, e: int) -> int:
            factor = 10 ** (e - common)
            if abs(v) > cls._max // factor: raise PipelineRejected("independent_scale_overflow")
            return v * factor
        left, right = adjusted(left, left_e), adjusted(right, right_e)
        passed = {"<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right, "==": left == right}[predicate["operator"]]
        result = predicate["outcome_if_true"] if passed else predicate["outcome_if_false"]
        if result not in {"YES", "NO", "INVALID"}: raise PipelineRejected("independent_outcome_invalid")
        return result

    def verify(self, definition: Mapping[str, Any], evidence: Mapping[str, Any], trust_model: Mapping[str, Any]) -> VerificationReport:
        now = str(self.clock_ms() if self.clock_ms else evidence.get("acquired_at_ms", "0"))
        checks: list[Mapping[str, Any]] = []
        try:
            resolver_v2.validate_resolver_definition(definition); resolver_v2._validate_trust_model(trust_model)
            if definition["trust_model"] != trust_model or definition["resolver_type"] not in {"pyth", "chainlink"}: raise PipelineRejected("independent_oracle_type_or_trust_mismatch")
            if evidence.get("definition_hash") != resolver_v2.resolver_definition_hash(definition).hex(): raise PipelineRejected("independent_resolver_hash_mismatch")
            source, row, kind = definition["source"], resolver_v2.parse_canonical_json(bytes.fromhex(str(evidence["payload_hex"]))), definition["resolver_type"]
            if kind == "pyth":
                expected = {"feed_id", "network", "cluster_genesis_hash", "price_exponent", "max_publish_age_ms", "max_confidence_bps", "predicate", "outcome_mapping", "account_schema_version", "adapter_version"}
                fields = {"account_schema_version", "cluster_genesis_hash", "confidence", "exponent", "feed_id", "network", "price", "publish_slot", "publish_time_ms", "raw_data_hash", "status"}
                if set(source) != expected or set(row) != fields or row["status"] != "TRADING": raise PipelineRejected("independent_pyth_format_or_status")
                if any(row[k] != source[k] for k in ("feed_id", "network", "cluster_genesis_hash", "account_schema_version")) or row["exponent"] != source["price_exponent"]: raise PipelineRejected("independent_pyth_binding")
                price, confidence = self._number(row["price"], "price"), self._number(row["confidence"], "confidence")
                if price == 0 or confidence < 0 or confidence * 10000 > abs(price) * int(source["max_confidence_bps"]): raise PipelineRejected("independent_pyth_confidence")
                timestamp, slot, outcome = row["publish_time_ms"], row["publish_slot"], self._outcome(row["price"], row["exponent"], source["predicate"])
                if int(now) > int(timestamp) + int(source["max_publish_age_ms"]): raise PipelineRejected("independent_pyth_stale")
                valid_until, facts = str(int(timestamp) + int(source["max_publish_age_ms"])), {"oracle": "pyth", "feed_id": row["feed_id"], "network": row["network"], "observed_value": row["price"], "exponent": row["exponent"], "confidence": row["confidence"], "source_timestamp_ms": timestamp, "publish_slot": slot, "raw_data_hash": row["raw_data_hash"], "predicate": source["predicate"]}
            else:
                expected = {"feed_id", "network", "cluster_genesis_hash", "decimals", "max_answer_age_ms", "require_round_metadata", "predicate", "outcome_mapping", "data_source_version", "adapter_version"}
                fields = {"answer", "answered_in_round", "cluster_genesis_hash", "data_source_version", "decimals", "feed_id", "network", "raw_data_hash", "round_id", "updated_at_ms"}
                if set(source) != expected or set(row) != fields: raise PipelineRejected("independent_chainlink_format")
                if any(row[k] != source[k] for k in ("feed_id", "network", "cluster_genesis_hash", "decimals", "data_source_version")): raise PipelineRejected("independent_chainlink_binding")
                if source["require_round_metadata"] and (int(row["round_id"]) == 0 or int(row["answered_in_round"]) < int(row["round_id"])): raise PipelineRejected("independent_chainlink_round")
                timestamp, slot = row["updated_at_ms"], row["round_id"]
                if int(now) > int(timestamp) + int(source["max_answer_age_ms"]): raise PipelineRejected("independent_chainlink_stale")
                outcome = self._outcome(row["answer"], str(-int(row["decimals"])), source["predicate"])
                valid_until, facts = str(int(timestamp) + int(source["max_answer_age_ms"])), {"oracle": "chainlink", "feed_id": row["feed_id"], "network": row["network"], "observed_value": row["answer"], "decimals": row["decimals"], "source_timestamp_ms": timestamp, "round_id": slot, "answered_in_round": row["answered_in_round"], "raw_data_hash": row["raw_data_hash"], "predicate": source["predicate"]}
            checks.append(_check("independent_oracle_binding", True, _digest(resolver_v2.canonical_json_bytes(source)), _digest(resolver_v2.canonical_json_bytes(source))))
            return VerificationReport(outcome, "VERIFIED", "high", checks, self.descriptor, facts, now, now, valid_until)
        except (PipelineRejected, ValueError, KeyError, resolver_v2.ResolverV2Error) as exc:
            return self._reject(str(exc), now, checks)
