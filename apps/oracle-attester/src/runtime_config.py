"""Strict, immutable public configuration for Resolver V2 verifier runtimes."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit
from solders.pubkey import Pubkey

import yaml

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2
from .resolver_v2_pipeline import PipelineRejected

_ADAPTERS = frozenset(("zktls", "signed-oracle", "pyth", "chainlink"))

class RuntimeConfigError(ValueError): pass

def _obj(value: Any, keys: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RuntimeConfigError(f"{name} has unknown or missing fields")
    return value

def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip(): raise RuntimeConfigError(f"{name} must be non-empty text")
    return value

def _positive(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0: raise RuntimeConfigError(f"{name} must be a positive integer")
    return value

@dataclass(frozen=True)
class SolanaRuntimeConfig: cluster: str; genesis_hash: str; prophet_program_id: str
@dataclass(frozen=True)
class VerifierRuntimeIdentity: implementation_id: str; version: str
@dataclass(frozen=True)
class Limits: request_max_bytes: int; request_timeout_seconds: int
@dataclass(frozen=True)
class Freshness: default_max_evidence_age_seconds: int; default_max_verification_age_seconds: int
@dataclass(frozen=True)
class InternalAuth: token_env: str
@dataclass(frozen=True)
class CoordinatorVerifierServiceConfig:
    base_url: str; auth_token_env: str; expected_verifier_id: str; expected_verifier_version: str; expected_verifier_implementation_digest: str; request_timeout_seconds: int
@dataclass(frozen=True)
class CoordinatorRuntimeConfig:
    verifier_a: CoordinatorVerifierServiceConfig; verifier_b: CoordinatorVerifierServiceConfig; sqlite_path: str; internal_auth: InternalAuth; request_timeout_seconds: int
@dataclass(frozen=True)
class VaultSignerConfig:
    signer_id: str; key_name: str; expected_public_key: str; expected_key_version: int; key_epochs: tuple["VaultSignerKeyEpoch", ...]
@dataclass(frozen=True)
class VaultSignerKeyEpoch:
    key_version: int; public_key: str; activation_time_ms: int; retirement_time_ms: int|None
@dataclass(frozen=True)
class VaultSigningConfig:
    address: str; token_env: str; transit_mount: str; request_timeout_seconds: int; backend: str; signer_a: VaultSignerConfig; signer_b: VaultSignerConfig; journal_path: str|None
@dataclass(frozen=True)
class SignedOracleRuntimeConfig: registry_path: str; registry_fingerprint: str; key_bindings: tuple[object, ...]
@dataclass(frozen=True)
class ZkTlsRuntimeConfig: provider_id: str; verifier_backend: str; allowed_proof_versions: tuple[str, ...]
@dataclass(frozen=True)
class ResolverRuntimeConfig:
    schema_version: int; environment: str; mode: str; solana: SolanaRuntimeConfig
    resolver_v2_schema_version: int; verifier: VerifierRuntimeIdentity; allowed_adapters: tuple[str, ...]
    limits: Limits; freshness: Freshness; internal_auth: InternalAuth; signed_oracle: SignedOracleRuntimeConfig|None; zktls: ZkTlsRuntimeConfig|None; coordinator: CoordinatorRuntimeConfig|None; signing: VaultSigningConfig|None
    def fingerprint(self) -> str:
        client = lambda value: {"base_url":value.base_url,"auth_token_env":value.auth_token_env,"expected_verifier_id":value.expected_verifier_id,"expected_verifier_version":value.expected_verifier_version,"expected_verifier_implementation_digest":value.expected_verifier_implementation_digest,"request_timeout_seconds":str(value.request_timeout_seconds)}
        signer = lambda value: {"signer_id":value.signer_id,"key_name":value.key_name,"expected_public_key":value.expected_public_key,"expected_key_version":str(value.expected_key_version),"key_epochs":[{"key_version":str(epoch.key_version),"public_key":epoch.public_key,"activation_time_ms":str(epoch.activation_time_ms),"retirement_time_ms":"" if epoch.retirement_time_ms is None else str(epoch.retirement_time_ms)} for epoch in value.key_epochs]}
        payload = {"environment":self.environment,"solana":{"cluster":self.solana.cluster,"genesis_hash":self.solana.genesis_hash,"prophet_program_id":self.solana.prophet_program_id},"resolver_v2":{"schema_version":str(self.resolver_v2_schema_version)},"verifier":{"implementation_id":self.verifier.implementation_id,"version":self.verifier.version},"allowed_adapters":list(self.allowed_adapters),"limits":{"request_max_bytes":str(self.limits.request_max_bytes),"request_timeout_seconds":str(self.limits.request_timeout_seconds)},"freshness":{"default_max_evidence_age_seconds":str(self.freshness.default_max_evidence_age_seconds),"default_max_verification_age_seconds":str(self.freshness.default_max_verification_age_seconds)},"mode":self.mode,"signed_oracle_registry_fingerprint":"" if self.signed_oracle is None else self.signed_oracle.registry_fingerprint,"signed_oracle_bindings":[] if self.signed_oracle is None else [{"key_id":b.key_id,"key_set_version":b.key_set_version,"oracle_identity":b.oracle_identity} for b in self.signed_oracle.key_bindings],"zktls":None if self.zktls is None else {"provider_id":self.zktls.provider_id,"verifier_backend":self.zktls.verifier_backend,"allowed_proof_versions":list(self.zktls.allowed_proof_versions)},"coordinator":None if self.coordinator is None else {"verifier_a":client(self.coordinator.verifier_a),"verifier_b":client(self.coordinator.verifier_b),"sqlite_path":self.coordinator.sqlite_path,"internal_auth":{"token_env":self.coordinator.internal_auth.token_env},"request_timeout_seconds":str(self.coordinator.request_timeout_seconds)},"signing":None if self.signing is None else {"vault":{"address":self.signing.address,"auth":{"token_env":self.signing.token_env},"transit_mount":self.signing.transit_mount,"request_timeout_seconds":str(self.signing.request_timeout_seconds),"backend":self.signing.backend},"journal_path":self.signing.journal_path or "","signers":{"a":signer(self.signing.signer_a),"b":signer(self.signing.signer_b)}}}
        return hashlib.sha256(b"PROPHET_RESOLVER_RUNTIME_CONFIG_V1\0" + resolver_v2.canonical_json_bytes(payload)).hexdigest()

def _coordinator_client(value: Any, name: str) -> CoordinatorVerifierServiceConfig:
    row = _obj(value, {"base_url","auth_token_env","expected_verifier_id","expected_verifier_version","expected_verifier_implementation_digest","request_timeout_seconds"}, name)
    base_url = _text(row["base_url"], f"{name}.base_url")
    try:
        parsed = urlsplit(base_url)
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise RuntimeConfigError(f"{name}.base_url is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query or parsed.path not in {"", "/"} or port == 0:
        raise RuntimeConfigError(f"{name}.base_url is invalid")
    digest = _text(row["expected_verifier_implementation_digest"], f"{name}.expected_verifier_implementation_digest")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise RuntimeConfigError(f"{name}.expected_verifier_implementation_digest is invalid")
    identity = {"schema":"prophet.adapter-descriptor.v2","schema_version":"2.0.0","adapter_id":_text(row["expected_verifier_id"], f"{name}.expected_verifier_id"),"adapter_version":_text(row["expected_verifier_version"], f"{name}.expected_verifier_version"),"implementation_digest":digest}
    try:
        resolver_v2._validate_adapter(identity)
    except resolver_v2.ResolverV2Error as exc:
        raise RuntimeConfigError(f"{name}.expected verifier identity is invalid") from exc
    return CoordinatorVerifierServiceConfig(base_url, _text(row["auth_token_env"], f"{name}.auth_token_env"), identity["adapter_id"], identity["adapter_version"], digest, _positive(row["request_timeout_seconds"], f"{name}.request_timeout_seconds"))

def parse_runtime_config(raw: Any, *, enable_mainnet: bool = False) -> ResolverRuntimeConfig:
    required={"schema_version","environment","mode","solana","resolver_v2","verifier","allowed_adapters","limits","freshness","internal_auth"}
    if not isinstance(raw,dict) or not required.issubset(raw) or set(raw)-required-{"signed_oracle","zktls","coordinator","signing"}: raise RuntimeConfigError("runtime config has unknown or missing fields")
    top=raw
    if top["schema_version"] != 1: raise RuntimeConfigError("unsupported schema_version")
    environment, mode = _text(top["environment"],"environment"), _text(top["mode"],"mode")
    if environment not in {"localtest","public-devnet","mainnet"}: raise RuntimeConfigError("unsupported environment")
    if mode not in {"production","test"}: raise RuntimeConfigError("unsupported mode")
    if environment == "mainnet" and not enable_mainnet: raise RuntimeConfigError("mainnet configuration is disabled")
    s = _obj(top["solana"], {"cluster","genesis_hash","prophet_program_id"}, "solana")
    solana = SolanaRuntimeConfig(_text(s["cluster"],"solana.cluster"),_text(s["genesis_hash"],"solana.genesis_hash"),_text(s["prophet_program_id"],"solana.prophet_program_id"))
    if environment == "public-devnet" and solana.cluster != "devnet": raise RuntimeConfigError("public-devnet requires devnet cluster")
    r = _obj(top["resolver_v2"], {"schema_version"}, "resolver_v2")
    if r["schema_version"] != 2: raise RuntimeConfigError("unsupported Resolver V2 schema")
    v = _obj(top["verifier"], {"implementation_id","version"}, "verifier")
    adapters = top["allowed_adapters"]
    if not isinstance(adapters,list) or not adapters or any(not isinstance(a,str) or a not in _ADAPTERS for a in adapters) or len(adapters) != len(set(adapters)): raise RuntimeConfigError("allowed_adapters invalid")
    l = _obj(top["limits"], {"request_max_bytes","request_timeout_seconds"}, "limits"); f = _obj(top["freshness"], {"default_max_evidence_age_seconds","default_max_verification_age_seconds"}, "freshness")
    a = _obj(top["internal_auth"], {"token_env"}, "internal_auth")
    signed=None; zktls=None; coordinator=None; signing=None
    if "zktls" in adapters:
        if "zktls" not in top: raise RuntimeConfigError("zktls requires runtime configuration")
        zk=_obj(top["zktls"],{"provider_id","verifier_backend","allowed_proof_versions"},"zktls")
        versions=zk["allowed_proof_versions"]
        if not isinstance(versions,list) or not versions: raise RuntimeConfigError("zktls.allowed_proof_versions required")
        normalized=tuple(sorted(_text(version,"zktls.allowed_proof_versions") for version in versions))
        if len(normalized)!=len(set(normalized)): raise RuntimeConfigError("duplicate zktls proof version")
        backend=_text(zk["verifier_backend"],"zktls.verifier_backend")
        if mode=="production" and backend=="deterministic-test": raise RuntimeConfigError("production rejects test zktls backend")
        zktls=ZkTlsRuntimeConfig(_text(zk["provider_id"],"zktls.provider_id"),backend,normalized)
    if "signed-oracle" in adapters:
        from .signed_oracle_runtime_keys import LegacyKeyBinding, load_trusted_oracle_key_registry
        if "signed_oracle" not in top: raise RuntimeConfigError("signed-oracle requires registry")
        so=_obj(top["signed_oracle"],{"registry_path","key_bindings"},"signed_oracle"); path=_text(so["registry_path"],"signed_oracle.registry_path")
        if mode=="production" and ("test" in path.lower() or "fixture" in path.lower()): raise RuntimeConfigError("production rejects test registry")
        try:
            registry=load_trusted_oracle_key_registry(path); raw_bindings=so["key_bindings"]
            if not isinstance(raw_bindings,list) or not raw_bindings: raise RuntimeConfigError("signed-oracle bindings required")
            bindings=[]
            for item in raw_bindings:
                row=_obj(item,{"key_id","key_set_version","oracle_identity"},"signed-oracle binding")
                version=_text(row["key_set_version"],"key_set_version")
                bindings.append(LegacyKeyBinding(_text(row["key_id"],"key_id"),version,_text(row["oracle_identity"],"oracle_identity")))
            bindings=tuple(sorted(bindings,key=lambda b:(b.key_id,b.key_set_version,b.oracle_identity)))
            if len({(b.key_id,b.key_set_version) for b in bindings})!=len(bindings): raise RuntimeConfigError("duplicate signed-oracle binding")
            if any(b.oracle_identity not in {r.oracle_identity for r in registry.records} for b in bindings): raise RuntimeConfigError("unknown signed-oracle binding identity")
            signed=SignedOracleRuntimeConfig(path,registry.fingerprint(),bindings)
        except PipelineRejected as exc: raise RuntimeConfigError("signed-oracle registry invalid") from exc
    if "coordinator" in top:
        row=_obj(top["coordinator"], {"verifier_a","verifier_b","sqlite_path","internal_auth","request_timeout_seconds"}, "coordinator")
        verifier_a, verifier_b = _coordinator_client(row["verifier_a"], "coordinator.verifier_a"), _coordinator_client(row["verifier_b"], "coordinator.verifier_b")
        if (verifier_a.expected_verifier_id, verifier_a.expected_verifier_version, verifier_a.expected_verifier_implementation_digest) == (verifier_b.expected_verifier_id, verifier_b.expected_verifier_version, verifier_b.expected_verifier_implementation_digest):
            raise RuntimeConfigError("coordinator verifier identities must be distinct")
        sqlite_path=_text(row["sqlite_path"], "coordinator.sqlite_path")
        if environment == "public-devnet" and (sqlite_path == ":memory:" or not Path(sqlite_path).is_absolute()): raise RuntimeConfigError("public-devnet requires persistent absolute coordinator sqlite_path")
        coordinator_timeout=_positive(row["request_timeout_seconds"], "coordinator.request_timeout_seconds")
        if coordinator_timeout < verifier_a.request_timeout_seconds + verifier_b.request_timeout_seconds: raise RuntimeConfigError("coordinator.request_timeout_seconds is too short for sequential verifiers")
        coordinator=CoordinatorRuntimeConfig(verifier_a, verifier_b, sqlite_path, InternalAuth(_text(_obj(row["internal_auth"], {"token_env"}, "coordinator.internal_auth")["token_env"], "coordinator.internal_auth.token_env")), coordinator_timeout)
    if "signing" in top:
        row=top["signing"]
        if not isinstance(row, dict) or not {"vault", "signers"}.issubset(row) or set(row) - {"vault", "signers", "journal_path"}:
            raise RuntimeConfigError("signing has unknown or missing fields")
        vault=_obj(row["vault"], {"address","auth","transit_mount","request_timeout_seconds","backend"}, "signing.vault")
        address=_text(vault["address"], "signing.vault.address")
        try: parsed=urlsplit(address); host=parsed.hostname
        except ValueError as exc: raise RuntimeConfigError("signing.vault.address is invalid") from exc
        if not host or parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query or parsed.path not in {"","/"} or parsed.scheme not in {"http","https"}: raise RuntimeConfigError("signing.vault.address is invalid")
        backend=_text(vault["backend"], "signing.vault.backend")
        if backend not in {"vault-transit","deterministic-test"}: raise RuntimeConfigError("unsupported signing.vault.backend")
        if backend == "deterministic-test" and (environment != "localtest" or mode != "test"): raise RuntimeConfigError("test Vault backend is not allowed outside localtest")
        if backend == "vault-transit" and environment == "public-devnet" and parsed.scheme != "https": raise RuntimeConfigError("public-devnet Vault requires https")
        signers=_obj(row["signers"], {"a","b"}, "signing.signers")
        def parse_public(value, field):
            public=_text(value, field)
            try:
                if str(Pubkey.from_string(public)) != public: raise ValueError
            except Exception as exc: raise RuntimeConfigError(f"{field} is invalid") from exc
            return public
        def parse_signer(value, name):
            if not isinstance(value, dict): raise RuntimeConfigError(f"{name} has unknown or missing fields")
            legacy={"signer_id","key_name","expected_public_key","expected_key_version"}
            epoch_keys={"signer_id","key_name","key_epochs"}
            if set(value) == legacy:
                public=parse_public(value["expected_public_key"], f"{name}.expected_public_key")
                epoch=VaultSignerKeyEpoch(_positive(value["expected_key_version"], f"{name}.expected_key_version"), public, 0, None)
                return VaultSignerConfig(_text(value["signer_id"], f"{name}.signer_id"), _text(value["key_name"], f"{name}.key_name"), public, epoch.key_version, (epoch,))
            if set(value) != epoch_keys: raise RuntimeConfigError(f"{name} has unknown or missing fields")
            raw_epochs=value["key_epochs"]
            if not isinstance(raw_epochs, list) or not raw_epochs: raise RuntimeConfigError(f"{name}.key_epochs required")
            epochs=[]
            for item in raw_epochs:
                row=_obj(item,{"key_version","public_key","activation_time_ms","retirement_time_ms"},f"{name}.key_epochs")
                if isinstance(row["activation_time_ms"], bool) or not isinstance(row["activation_time_ms"], int) or row["activation_time_ms"] < 0: raise RuntimeConfigError(f"{name}.key_epochs activation_time_ms invalid")
                retirement=row["retirement_time_ms"]
                if retirement is not None and (isinstance(retirement,bool) or not isinstance(retirement,int) or retirement <= row["activation_time_ms"]): raise RuntimeConfigError(f"{name}.key_epochs retirement_time_ms invalid")
                epochs.append(VaultSignerKeyEpoch(_positive(row["key_version"], f"{name}.key_epochs key_version"),parse_public(row["public_key"],f"{name}.key_epochs public_key"),row["activation_time_ms"],retirement))
            epochs=tuple(sorted(epochs,key=lambda epoch: epoch.activation_time_ms))
            if len({epoch.key_version for epoch in epochs}) != len(epochs) or len({epoch.public_key for epoch in epochs}) != len(epochs): raise RuntimeConfigError(f"{name}.key_epochs duplicates")
            if any(epochs[index].key_version >= epochs[index + 1].key_version for index in range(len(epochs)-1)): raise RuntimeConfigError(f"{name}.key_epochs versions must increase")
            for index, epoch in enumerate(epochs[:-1]):
                following=epochs[index+1]
                if epoch.retirement_time_ms != following.activation_time_ms: raise RuntimeConfigError(f"{name}.key_epochs must be contiguous without overlap")
            if epochs[-1].retirement_time_ms is not None: raise RuntimeConfigError(f"{name}.key_epochs final epoch must remain active")
            active=epochs[-1]
            return VaultSignerConfig(_text(value["signer_id"], f"{name}.signer_id"), _text(value["key_name"], f"{name}.key_name"), active.public_key, active.key_version, epochs)
        signer_a, signer_b=parse_signer(signers["a"], "signing.signers.a"), parse_signer(signers["b"], "signing.signers.b")
        if signer_a.signer_id == signer_b.signer_id or signer_a.key_name == signer_b.key_name or signer_a.expected_public_key == signer_b.expected_public_key: raise RuntimeConfigError("Vault signer identities must be distinct")
        auth=_obj(vault["auth"], {"token_env"}, "signing.vault.auth")
        journal_path = None if "journal_path" not in row else _text(row["journal_path"], "signing.journal_path")
        if environment == "public-devnet" and (not journal_path or journal_path == ":memory:" or not Path(journal_path).is_absolute()): raise RuntimeConfigError("public-devnet requires persistent absolute signing journal_path")
        signing=VaultSigningConfig(address.rstrip("/"), _text(auth["token_env"], "signing.vault.auth.token_env"), _text(vault["transit_mount"], "signing.vault.transit_mount"), _positive(vault["request_timeout_seconds"], "signing.vault.request_timeout_seconds"), backend, signer_a, signer_b, journal_path)
    return ResolverRuntimeConfig(1,environment,mode,solana,2,VerifierRuntimeIdentity(_text(v["implementation_id"],"verifier.implementation_id"),_text(v["version"],"verifier.version")),tuple(sorted(adapters)),Limits(_positive(l["request_max_bytes"],"limits.request_max_bytes"),_positive(l["request_timeout_seconds"],"limits.request_timeout_seconds")),Freshness(_positive(f["default_max_evidence_age_seconds"],"freshness.default_max_evidence_age_seconds"),_positive(f["default_max_verification_age_seconds"],"freshness.default_max_verification_age_seconds")),InternalAuth(_text(a["token_env"],"internal_auth.token_env")),signed,zktls,coordinator,signing)

def load_runtime_config(path: str | Path) -> ResolverRuntimeConfig:
    try: raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc: raise RuntimeConfigError("unable to load runtime configuration") from exc
    return parse_runtime_config(raw)
