"""Immutable, public-only runtime trust registry for signed-oracle epochs."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Any
import yaml
from solders.pubkey import Pubkey
from .resolver_v2_pipeline import resolver_v2, PipelineRejected
from .resolver_v2_adapters import OracleKeyEpoch

_STATUSES=frozenset(("active","retired"))

@dataclass(frozen=True)
class TrustedOracleKey:
    oracle_identity:str; resolver_ids:tuple[str,...]; public_key:str; key_epoch:str
    activation_time_ms:str; retirement_time_ms:str|None; allowed_message_versions:tuple[str,...]; status:str="active"

class TrustedOracleKeyRegistry:
    def __init__(self, records:Iterable[TrustedOracleKey], *, overlap_ms:int=0):
        rows=tuple(records); self.records=tuple(sorted(rows,key=lambda r:(r.oracle_identity,int(r.activation_time_ms) if isinstance(r.activation_time_ms,str) and r.activation_time_ms.lstrip('-').isdigit() else -1,r.key_epoch,r.public_key))); self.overlap_ms=overlap_ms
        if not rows or isinstance(overlap_ms,bool) or not isinstance(overlap_ms,int) or overlap_ms<0: raise PipelineRejected("trusted_key_registry_invalid")
        seen_epochs=set(); seen_keys=set()
        for r in self.records:
            if not r.oracle_identity or not r.resolver_ids or not r.key_epoch or not r.allowed_message_versions or r.status not in _STATUSES: raise PipelineRejected("trusted_key_record_invalid")
            try: Pubkey.from_string(r.public_key); a=int(r.activation_time_ms); z=None if r.retirement_time_ms is None else int(r.retirement_time_ms)
            except Exception as e: raise PipelineRejected("trusted_key_record_invalid") from e
            if a<0 or z is not None and z<a or any(not x for x in r.resolver_ids+r.allowed_message_versions): raise PipelineRejected("trusted_key_record_invalid")
            key=(r.oracle_identity,r.key_epoch); pub=(r.oracle_identity,r.public_key)
            if key in seen_epochs or pub in seen_keys: raise PipelineRejected("trusted_key_duplicate")
            seen_epochs.add(key); seen_keys.add(pub)
        for identity in {r.oracle_identity for r in self.records}:
            rs=[r for r in self.records if r.oracle_identity==identity]
            for left,right in zip(rs,rs[1:]):
                if left.retirement_time_ms is None: raise PipelineRejected("trusted_key_unbounded_overlap")
                if int(right.activation_time_ms) < int(left.retirement_time_ms)-overlap_ms: raise PipelineRejected("trusted_key_overlap_invalid")
    def resolve(self, *, oracle_identity:str,resolver_id:str,message_version:str,source_timestamp_ms:str) -> TrustedOracleKey:
        try: at=int(source_timestamp_ms)
        except Exception as e: raise PipelineRejected("trusted_key_timestamp_invalid") from e
        matches=[r for r in self.records if r.oracle_identity==oracle_identity and resolver_id in r.resolver_ids and message_version in r.allowed_message_versions and r.status=="active" and at>=int(r.activation_time_ms) and (r.retirement_time_ms is None or at<int(r.retirement_time_ms))]
        if len(matches)!=1: raise PipelineRejected("trusted_key_not_resolved")
        return matches[0]
    def fingerprint(self)->str:
        rows=[{"oracle_identity":r.oracle_identity,"resolver_ids":list(r.resolver_ids),"public_key":r.public_key,"key_epoch":r.key_epoch,"activation_time_ms":r.activation_time_ms,"retirement_time_ms":r.retirement_time_ms,"allowed_message_versions":list(r.allowed_message_versions),"status":r.status} for r in self.records]
        return hashlib.sha256(b"PROPHET_SIGNED_ORACLE_RUNTIME_KEYS_V1\0"+resolver_v2.canonical_json_bytes({"overlap_ms":str(self.overlap_ms),"records":rows})).hexdigest()

@dataclass(frozen=True)
class LegacyKeyBinding:
    key_id:str; key_set_version:str; oracle_identity:str

class RegistryBackedOracleKeyring:
    """Legacy adapter keyring facade; trust selection remains in the registry."""
    def __init__(self, registry:TrustedOracleKeyRegistry, bindings:Iterable[LegacyKeyBinding], *, resolver_id:str, message_version:str):
        self.registry=registry; self.resolver_id=resolver_id; self.message_version=message_version
        rows=tuple(bindings); self.bindings={(r.key_id,r.key_set_version):r for r in rows}
        if not resolver_id or not message_version or not rows or len(self.bindings)!=len(rows): raise PipelineRejected("legacy_key_binding_invalid")
        identities={r.oracle_identity for r in registry.records}
        if any(not r.key_id or not r.key_set_version or r.oracle_identity not in identities for r in rows): raise PipelineRejected("legacy_key_binding_invalid")
    def resolve(self,key_id:str,at_ms:str,key_set_version:str)->OracleKeyEpoch:
        binding=self.bindings.get((key_id,key_set_version))
        if binding is None: raise PipelineRejected("unknown_oracle_key")
        record=self.registry.resolve(oracle_identity=binding.oracle_identity,resolver_id=self.resolver_id,message_version=self.message_version,source_timestamp_ms=at_ms)
        return OracleKeyEpoch(key_id=key_id,public_key=record.public_key,key_set_version=key_set_version,activates_at_ms=record.activation_time_ms,retires_at_ms=record.retirement_time_ms)

def load_trusted_oracle_key_registry(path: str | Path) -> TrustedOracleKeyRegistry:
    try: raw=yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError,yaml.YAMLError) as exc: raise PipelineRejected("trusted_key_registry_load_failed") from exc
    if not isinstance(raw,dict) or set(raw)!={"overlap_ms","records"} or not isinstance(raw["records"],list): raise PipelineRejected("trusted_key_registry_format_invalid")
    try:
        return TrustedOracleKeyRegistry([TrustedOracleKey(r["oracle_identity"],tuple(r["resolver_ids"]),r["public_key"],r["key_epoch"],r["activation_time_ms"],r.get("retirement_time_ms"),tuple(r["allowed_message_versions"]),r.get("status","active")) for r in raw["records"]],overlap_ms=raw["overlap_ms"])
    except (KeyError,TypeError) as exc: raise PipelineRejected("trusted_key_registry_format_invalid") from exc
