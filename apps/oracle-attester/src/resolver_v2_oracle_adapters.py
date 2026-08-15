"""Fail-closed Pyth and Chainlink Resolver V2 adapters.

These adapters acquire immutable oracle observations and verify only canonical
evidence.  They never access a signer, construct a settlement message, or use
floating point arithmetic.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from .resolver_v2_pipeline import AcquiredEvidence, PipelineRejected, VerificationReport

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


OUTCOMES = frozenset(("YES", "NO", "INVALID"))
MAX_FIXED = (1 << 127) - 1
_INTEGER = re.compile(r"-?(0|[1-9][0-9]*)$")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise PipelineRejected(f"{name}_invalid")
    return value


def _uint(value: Any, name: str) -> int:
    try:
        resolver_v2._uint(value, name)
        return int(value)
    except (ValueError, resolver_v2.ResolverV2Error) as exc:
        raise PipelineRejected(str(exc)) from exc


def _sint(value: Any, name: str) -> int:
    if not isinstance(value, str) or not _INTEGER.fullmatch(value):
        raise PipelineRejected(f"{name}_invalid")
    number = int(value)
    if abs(number) > MAX_FIXED:
        raise PipelineRejected(f"{name}_overflow")
    return number


def _descriptor(value: Mapping[str, Any], trust: bool = False) -> Mapping[str, Any]:
    try:
        return resolver_v2._validate_trust_model(value) if trust else resolver_v2._validate_adapter(value)
    except resolver_v2.ResolverV2Error as exc:
        raise PipelineRejected(str(exc)) from exc


def _metric(metrics: Any, name: str, *, labels: Optional[dict[str, str]] = None, value: Optional[float] = None) -> None:
    if metrics is None:
        return
    if value is None:
        metrics.inc(name, labels=labels)
    else:
        metrics.observe_histogram(name, value, labels=labels)


def validate_numeric_predicate(predicate: Mapping[str, Any]) -> None:
    """The single Pyth/Chainlink numeric predicate schema.

    Values are signed integer mantissas; exponents are decimal powers.  The
    comparison is exact after multiplying both mantissas to the lower exponent.
    """
    required = {"operator", "threshold_value", "threshold_exponent", "outcome_if_true", "outcome_if_false"}
    if set(predicate) != required or predicate.get("operator") not in {"<", "<=", ">", ">=", "=="}:
        raise PipelineRejected("numeric_predicate_schema_invalid")
    _sint(predicate["threshold_value"], "threshold_value")
    exponent = _sint(predicate["threshold_exponent"], "threshold_exponent")
    if exponent < -255 or exponent > 255:
        raise PipelineRejected("threshold_exponent_out_of_range")
    if predicate["outcome_if_true"] not in OUTCOMES or predicate["outcome_if_false"] not in OUTCOMES:
        raise PipelineRejected("numeric_predicate_outcome_invalid")


def evaluate_numeric_predicate(value: str, exponent: str, predicate: Mapping[str, Any]) -> str:
    """Exact fixed-point comparison; explicitly rejects scaling overflow."""
    validate_numeric_predicate(predicate)
    left, left_exp = _sint(value, "observed_value"), _sint(exponent, "observed_exponent")
    right, right_exp = _sint(predicate["threshold_value"], "threshold_value"), _sint(predicate["threshold_exponent"], "threshold_exponent")
    if not -255 <= left_exp <= 255:
        raise PipelineRejected("observed_exponent_out_of_range")
    common = min(left_exp, right_exp)
    def scale(number: int, places: int) -> int:
        factor = 10 ** places
        if abs(number) > MAX_FIXED // factor:
            raise PipelineRejected("fixed_point_scale_overflow")
        return number * factor
    left, right = scale(left, left_exp - common), scale(right, right_exp - common)
    op = predicate["operator"]
    passed = {"<": left < right, "<=": left <= right, ">": left > right, ">=": left >= right, "==": left == right}[op]
    return predicate["outcome_if_true"] if passed else predicate["outcome_if_false"]


def _report(adapter: Mapping[str, Any], *, outcome: str, now: str, valid_until: str, facts: Mapping[str, Any], failure: Optional[str] = None) -> VerificationReport:
    return VerificationReport(outcome if failure is None else "INVALID", "VERIFIED" if failure is None else "REJECTED", "high" if failure is None else "none", [], adapter, facts if failure is None else {"failure_code": failure}, now, now, valid_until if failure is None else now, failure, None)


class _OracleAdapter:
    resolver_type = ""
    source_name = ""

    def __init__(self, *, adapter_digest: str, verifier_descriptor: Mapping[str, Any], clock_ms: Optional[Callable[[], int]] = None, metrics: Any = None):
        self.adapter_digest, self.verifier_descriptor = _hex(adapter_digest, "adapter_digest"), dict(_descriptor(verifier_descriptor))
        self.clock_ms, self.metrics = clock_ms, metrics

    def _definition(self, definition: Mapping[str, Any], trust_model: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
        try:
            resolver_v2.validate_resolver_definition(definition)
        except resolver_v2.ResolverV2Error as exc:
            raise PipelineRejected(str(exc)) from exc
        if definition["resolver_type"] != self.resolver_type:
            raise PipelineRejected("wrong_resolver_type")
        if definition["adapter"]["implementation_digest"] != self.adapter_digest:
            raise PipelineRejected("adapter_digest_mismatch")
        if "adapter_version" in definition["source"] and definition["source"]["adapter_version"] != definition["adapter"]["adapter_version"]:
            raise PipelineRejected("adapter_version_mismatch")
        if trust_model is not None:
            _descriptor(trust_model, True)
            if definition["trust_model"] != trust_model:
                raise PipelineRejected("trust_model_mismatch")
        return definition["source"]

    def _failure(self, code: str, now: str) -> VerificationReport:
        _metric(self.metrics, "prophet_resolver_v2_oracle_resolution_total", labels={"adapter": self.source_name, "result": "failure", "reason": code})
        if "stale" in code: _metric(self.metrics, "prophet_resolver_v2_oracle_stale_observation_total", labels={"adapter": self.source_name})
        if "confidence" in code: _metric(self.metrics, "prophet_resolver_v2_oracle_invalid_confidence_total", labels={"adapter": self.source_name})
        return _report(self.verifier_descriptor, outcome="INVALID", now=now, valid_until=now, facts={}, failure=code)


@dataclass(frozen=True)
class PythMaterial:
    feed_id: str
    network: str
    cluster_genesis_hash: str
    price: str
    exponent: str
    confidence: str
    status: str
    publish_time_ms: str
    publish_slot: str
    raw_data: bytes
    acquired_at_ms: str


class PythAdapter(_OracleAdapter):
    resolver_type, source_name = "pyth", "pyth"

    @staticmethod
    def _source(source: Mapping[str, Any]) -> None:
        required = {"feed_id", "network", "cluster_genesis_hash", "price_exponent", "max_publish_age_ms", "max_confidence_bps", "predicate", "outcome_mapping", "account_schema_version", "adapter_version"}
        if set(source) != required: raise PipelineRejected("pyth_source_schema_mismatch")
        _hex(source["feed_id"], "feed_id"); _hex(source["cluster_genesis_hash"], "cluster_genesis_hash")
        if not isinstance(source["network"], str) or not source["network"] or not isinstance(source["account_schema_version"], str) or not isinstance(source["adapter_version"], str): raise PipelineRejected("pyth_source_identity_invalid")
        exp = _sint(source["price_exponent"], "price_exponent")
        if not -255 <= exp <= 255: raise PipelineRejected("pyth_exponent_out_of_range")
        _uint(source["max_publish_age_ms"], "max_publish_age_ms"); _uint(source["max_confidence_bps"], "max_confidence_bps")
        if source["outcome_mapping"] != {"numeric_predicate": "v1"}: raise PipelineRejected("pyth_outcome_mapping_invalid")
        validate_numeric_predicate(source["predicate"])

    def acquire(self, definition: Mapping[str, Any], material: PythMaterial) -> AcquiredEvidence:
        started = time.perf_counter()
        try:
            source = self._definition(definition); self._source(source)
            if (material.feed_id, material.network, material.cluster_genesis_hash, material.exponent) != (source["feed_id"], source["network"], source["cluster_genesis_hash"], source["price_exponent"]): raise PipelineRejected("pyth_acquisition_binding_mismatch")
            _sint(material.price, "price"); _uint(material.confidence, "confidence"); _uint(material.publish_time_ms, "publish_time_ms"); _uint(material.publish_slot, "publish_slot"); _uint(material.acquired_at_ms, "acquired_at_ms")
            payload = {"account_schema_version": source["account_schema_version"], "cluster_genesis_hash": material.cluster_genesis_hash, "confidence": material.confidence, "exponent": material.exponent, "feed_id": material.feed_id, "network": material.network, "price": material.price, "publish_slot": material.publish_slot, "publish_time_ms": material.publish_time_ms, "raw_data_hash": _hash(material.raw_data), "status": material.status}
            raw = resolver_v2.canonical_json_bytes(payload)
            return AcquiredEvidence(self.adapter_digest, definition["resolver_id"], material.feed_id, material.acquired_at_ms, raw, {"feed_id": material.feed_id, "network": material.network, "publish_slot": material.publish_slot, "raw_data_hash": payload["raw_data_hash"]}, source_time_ms=material.publish_time_ms, source_sequence=material.publish_slot, acquisition_id=f"pyth-{_hash(raw)}")
        except PipelineRejected:
            _metric(self.metrics, "prophet_resolver_v2_oracle_fetch_failures_total", labels={"adapter": "pyth"}); raise
        finally: _metric(self.metrics, "prophet_resolver_v2_oracle_adapter_latency_seconds", labels={"adapter": "pyth"}, value=time.perf_counter()-started)

    def verify(self, definition: Mapping[str, Any], evidence: Mapping[str, Any], trust_model: Mapping[str, Any]) -> VerificationReport:
        now = str(self.clock_ms() if self.clock_ms else evidence.get("acquired_at_ms", "0")); started = time.perf_counter()
        try:
            source = self._definition(definition, trust_model); self._source(source)
            if evidence.get("definition_hash") != resolver_v2.resolver_definition_hash(definition).hex(): raise PipelineRejected("resolver_hash_mismatch")
            row = resolver_v2.parse_canonical_json(bytes.fromhex(str(evidence["payload_hex"])))
            required = {"account_schema_version", "cluster_genesis_hash", "confidence", "exponent", "feed_id", "network", "price", "publish_slot", "publish_time_ms", "raw_data_hash", "status"}
            if set(row) != required: raise PipelineRejected("pyth_malformed_account_data")
            _hex(row["raw_data_hash"], "raw_data_hash")
            if any(row[key] != source[key] for key in ("feed_id", "network", "cluster_genesis_hash", "account_schema_version")): raise PipelineRejected("pyth_feed_or_network_mismatch")
            if row["exponent"] != source["price_exponent"]: raise PipelineRejected("pyth_exponent_mismatch")
            if row["status"] != "TRADING": raise PipelineRejected("pyth_invalid_status")
            price, confidence = _sint(row["price"], "price"), _uint(row["confidence"], "confidence")
            if price == 0 or confidence * 10_000 > abs(price) * _uint(source["max_confidence_bps"], "max_confidence_bps"): raise PipelineRejected("pyth_confidence_rejected")
            if _uint(now, "now_ms") > _uint(row["publish_time_ms"], "publish_time_ms") + _uint(source["max_publish_age_ms"], "max_publish_age_ms"): raise PipelineRejected("pyth_stale_publish_time")
            outcome = evaluate_numeric_predicate(row["price"], row["exponent"], source["predicate"])
            valid_until = str(_uint(row["publish_time_ms"], "publish_time_ms") + _uint(source["max_publish_age_ms"], "max_publish_age_ms"))
            facts = {"oracle": "pyth", "feed_id": row["feed_id"], "network": row["network"], "observed_value": row["price"], "exponent": row["exponent"], "confidence": row["confidence"], "source_timestamp_ms": row["publish_time_ms"], "publish_slot": row["publish_slot"], "raw_data_hash": row["raw_data_hash"], "predicate": source["predicate"]}
            _metric(self.metrics, "prophet_resolver_v2_oracle_resolution_total", labels={"adapter": "pyth", "result": "success"})
            return _report(self.verifier_descriptor, outcome=outcome, now=now, valid_until=valid_until, facts=facts)
        except (PipelineRejected, ValueError, KeyError, resolver_v2.ResolverV2Error) as exc: return self._failure(str(exc), now)
        finally: _metric(self.metrics, "prophet_resolver_v2_oracle_adapter_latency_seconds", labels={"adapter": "pyth"}, value=time.perf_counter()-started)


@dataclass(frozen=True)
class ChainlinkMaterial:
    feed_id: str
    network: str
    cluster_genesis_hash: str
    answer: str
    decimals: str
    updated_at_ms: str
    round_id: str
    answered_in_round: str
    raw_data: bytes
    acquired_at_ms: str


class ChainlinkAdapter(_OracleAdapter):
    resolver_type, source_name = "chainlink", "chainlink"

    @staticmethod
    def _source(source: Mapping[str, Any]) -> None:
        required = {"feed_id", "network", "cluster_genesis_hash", "decimals", "max_answer_age_ms", "require_round_metadata", "predicate", "outcome_mapping", "data_source_version", "adapter_version"}
        if set(source) != required: raise PipelineRejected("chainlink_source_schema_mismatch")
        _hex(source["feed_id"], "feed_id"); _hex(source["cluster_genesis_hash"], "cluster_genesis_hash"); _uint(source["decimals"], "decimals"); _uint(source["max_answer_age_ms"], "max_answer_age_ms")
        if int(source["decimals"]) > 255 or not isinstance(source["network"], str) or not source["network"] or not isinstance(source["data_source_version"], str) or not isinstance(source["adapter_version"], str) or not isinstance(source["require_round_metadata"], bool): raise PipelineRejected("chainlink_source_identity_invalid")
        if source["outcome_mapping"] != {"numeric_predicate": "v1"}: raise PipelineRejected("chainlink_outcome_mapping_invalid")
        validate_numeric_predicate(source["predicate"])

    def acquire(self, definition: Mapping[str, Any], material: ChainlinkMaterial) -> AcquiredEvidence:
        started = time.perf_counter()
        try:
            source = self._definition(definition); self._source(source)
            if (material.feed_id, material.network, material.cluster_genesis_hash, material.decimals) != (source["feed_id"], source["network"], source["cluster_genesis_hash"], source["decimals"]): raise PipelineRejected("chainlink_acquisition_binding_mismatch")
            _sint(material.answer, "answer"); [_uint(getattr(material, name), name) for name in ("updated_at_ms", "round_id", "answered_in_round", "acquired_at_ms")]
            payload = {"answer": material.answer, "answered_in_round": material.answered_in_round, "cluster_genesis_hash": material.cluster_genesis_hash, "data_source_version": source["data_source_version"], "decimals": material.decimals, "feed_id": material.feed_id, "network": material.network, "raw_data_hash": _hash(material.raw_data), "round_id": material.round_id, "updated_at_ms": material.updated_at_ms}
            raw = resolver_v2.canonical_json_bytes(payload)
            return AcquiredEvidence(self.adapter_digest, definition["resolver_id"], material.feed_id, material.acquired_at_ms, raw, {"feed_id": material.feed_id, "network": material.network, "round_id": material.round_id, "raw_data_hash": payload["raw_data_hash"]}, source_time_ms=material.updated_at_ms, source_sequence=material.round_id, acquisition_id=f"chainlink-{_hash(raw)}")
        except PipelineRejected:
            _metric(self.metrics, "prophet_resolver_v2_oracle_fetch_failures_total", labels={"adapter": "chainlink"}); raise
        finally: _metric(self.metrics, "prophet_resolver_v2_oracle_adapter_latency_seconds", labels={"adapter": "chainlink"}, value=time.perf_counter()-started)

    def verify(self, definition: Mapping[str, Any], evidence: Mapping[str, Any], trust_model: Mapping[str, Any]) -> VerificationReport:
        now = str(self.clock_ms() if self.clock_ms else evidence.get("acquired_at_ms", "0")); started = time.perf_counter()
        try:
            source = self._definition(definition, trust_model); self._source(source)
            if evidence.get("definition_hash") != resolver_v2.resolver_definition_hash(definition).hex(): raise PipelineRejected("resolver_hash_mismatch")
            row = resolver_v2.parse_canonical_json(bytes.fromhex(str(evidence["payload_hex"])))
            required = {"answer", "answered_in_round", "cluster_genesis_hash", "data_source_version", "decimals", "feed_id", "network", "raw_data_hash", "round_id", "updated_at_ms"}
            if set(row) != required: raise PipelineRejected("chainlink_malformed_data")
            _hex(row["raw_data_hash"], "raw_data_hash")
            if any(row[key] != source[key] for key in ("feed_id", "network", "cluster_genesis_hash", "decimals", "data_source_version")): raise PipelineRejected("chainlink_feed_or_network_mismatch")
            _sint(row["answer"], "answer"); _uint(row["updated_at_ms"], "updated_at_ms"); round_id, answered = _uint(row["round_id"], "round_id"), _uint(row["answered_in_round"], "answered_in_round")
            if source["require_round_metadata"] and (round_id == 0 or answered < round_id): raise PipelineRejected("chainlink_invalid_round_metadata")
            if _uint(now, "now_ms") > _uint(row["updated_at_ms"], "updated_at_ms") + _uint(source["max_answer_age_ms"], "max_answer_age_ms"): raise PipelineRejected("chainlink_stale_answer")
            outcome = evaluate_numeric_predicate(row["answer"], str(-int(row["decimals"])), source["predicate"])
            valid_until = str(_uint(row["updated_at_ms"], "updated_at_ms") + _uint(source["max_answer_age_ms"], "max_answer_age_ms"))
            facts = {"oracle": "chainlink", "feed_id": row["feed_id"], "network": row["network"], "observed_value": row["answer"], "decimals": row["decimals"], "source_timestamp_ms": row["updated_at_ms"], "round_id": row["round_id"], "answered_in_round": row["answered_in_round"], "raw_data_hash": row["raw_data_hash"], "predicate": source["predicate"]}
            _metric(self.metrics, "prophet_resolver_v2_oracle_resolution_total", labels={"adapter": "chainlink", "result": "success"})
            return _report(self.verifier_descriptor, outcome=outcome, now=now, valid_until=valid_until, facts=facts)
        except (PipelineRejected, ValueError, KeyError, resolver_v2.ResolverV2Error) as exc: return self._failure(str(exc), now)
        finally: _metric(self.metrics, "prophet_resolver_v2_oracle_adapter_latency_seconds", labels={"adapter": "chainlink"}, value=time.perf_counter()-started)
