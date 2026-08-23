"""Read-only per-signer authorization core; it deliberately has no signing side effects."""
from __future__ import annotations
import hashlib, struct
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from solders.pubkey import Pubkey
from prophet_sdk.pdas import derive_market_pda, derive_notary_config_snapshot_pda
from prophet_sdk.settlement_message import build_resolution_message_v2
from .verifier_attestation import VerifierAttestationError, settlement_authorization_job_id, verify_attestation

AUTHORIZATION_SCHEMA = "PROPHET_SETTLEMENT_AUTHORIZATION_V1"
AUTHORIZATION_VERSION = "1"
MARKET_DISC = hashlib.sha256(b"account:Market").digest()[:8]
NOTARY_DISC = hashlib.sha256(b"account:NotaryConfig").digest()[:8]
class SignerAuthorizationError(ValueError): pass

@dataclass(frozen=True)
class VerifierPin: public_key: str; verifier_id: str; verifier_version: str; implementation_digest: str
@dataclass(frozen=True)
class SignerAuthorizationConfig:
    signer_slot: str; own_notary_public_key: str; counterpart_notary_public_key: str
    verifier_a: VerifierPin; verifier_b: VerifierPin; expected_cluster_genesis_hash: str; expected_program_id: str
@dataclass(frozen=True)
class Account: owner: str; data: bytes
@dataclass(frozen=True)
class FinalizedAccountRead:
    """One finalized account response with the RPC context slot that produced it."""
    account: Account|None; context_slot: int
@dataclass(frozen=True)
class FinalizedAccountsRead:
    """A single-bank finalized multi-account response used as authorization truth."""
    accounts: Mapping[str, Account|None]; context_slot: int
class FinalizedRpc(Protocol):
    def genesis_hash(self) -> str: ...
    def finalized_slot(self) -> int: ...
    def block_time(self, slot: int) -> int|None: ...
    def finalized_account(self, pubkey: str, *, min_context_slot: int) -> FinalizedAccountRead: ...
    def finalized_accounts(self, pubkeys: tuple[str, str], *, min_context_slot: int) -> FinalizedAccountsRead: ...
@dataclass(frozen=True)
class AuthorizationResult:
    settlement_authorization_job_id: str; market: str; notary_config: str; outcome: str; canonical_message_bytes: bytes; canonical_message_digest: str; signer_slot: str; own_notary_public_key: str

def _pk(value: Any, name: str) -> str:
    try:
        if not isinstance(value, str) or str(Pubkey.from_string(value)) != value: raise ValueError
    except Exception as exc: raise SignerAuthorizationError(f"{name}_invalid") from exc
    return value
def _hex(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value): raise SignerAuthorizationError(f"{name}_invalid")
    return value
def parse_request(value: Mapping[str, Any]) -> dict[str, Any]:
    required={"schema","version","cluster_genesis_hash","program_id","market","verifier_a_attestation","verifier_b_attestation"}
    if not isinstance(value, Mapping) or set(value) != required or value["schema"] != AUTHORIZATION_SCHEMA or value["version"] != AUTHORIZATION_VERSION: raise SignerAuthorizationError("authorization_request_invalid")
    return {**dict(value), "cluster_genesis_hash": _hex(value["cluster_genesis_hash"], "request_genesis"), "program_id": _pk(value["program_id"], "request_program"), "market": _pk(value["market"], "request_market")}
def _market(raw: bytes) -> dict[str, Any]:
    if len(raw) != 8 + 416 or raw[:8] != MARKET_DISC: raise SignerAuthorizationError("market_malformed")
    d=raw[8:]; p=0
    keys=[]
    for _ in range(6): keys.append(str(Pubkey.from_bytes(d[p:p+32]))); p+=32
    resolver=d[p:p+32]; p+=96
    open_ts,lock_ts,resolve_ts,resolved_ts=struct.unpack_from("<qqqq",d,p); p+=32
    p+=8*4+4*2+2*2+6+1; status,outcome,bump,remainder=struct.unpack_from("<BBBB",d,p); p+=4
    # Anchor's enums have no catch-all variant.  Never treat an unknown raw
    # discriminant as a non-resolved/pre-resolution state.
    if status not in (0, 1, 2) or outcome not in (0, 1, 2, 3):
        raise SignerAuthorizationError("market_malformed")
    creator=str(Pubkey.from_bytes(d[p:p+32])); nonce=struct.unpack_from("<Q",d,p+32)[0]
    return {"notary_config":keys[5],"resolver_hash":resolver,"open_ts":open_ts,"lock_ts":lock_ts,"resolve_ts":resolve_ts,"resolved_ts":resolved_ts,"status":status,"outcome":outcome,"bump":bump,"remainder":remainder,"creator":creator,"nonce":nonce,"proof":d[224:256],"inputs":d[256:288]}
def _notary(raw: bytes) -> dict[str, Any]:
    if len(raw) < 8+48 or raw[:8] != NOTARY_DISC: raise SignerAuthorizationError("notary_malformed")
    d=raw[8:]; admin=str(Pubkey.from_bytes(d[:32])); threshold,count,bump=d[32],d[33],d[34]; version=struct.unpack_from("<Q",d,40)[0]
    if count > 32 or len(d) != 48 + 32 * 32: raise SignerAuthorizationError("notary_malformed")
    return {"admin":admin,"threshold":threshold,"count":count,"bump":bump,"version":version,"keys":[str(Pubkey.from_bytes(d[48+i*32:80+i*32])) for i in range(count)]}
def _slot(value: Any, name: str, minimum: int=0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SignerAuthorizationError(f"{name}_invalid")
    return value
def _finalized_account_read(value: Any, *, minimum: int) -> FinalizedAccountRead:
    if not isinstance(value, FinalizedAccountRead): raise SignerAuthorizationError("finalized_account_read_invalid")
    _slot(value.context_slot, "finalized_account_context_slot", minimum)
    if value.account is not None and not isinstance(value.account, Account): raise SignerAuthorizationError("finalized_account_invalid")
    return value
def _finalized_accounts_read(value: Any, *, market: str, notary_config: str, minimum: int) -> FinalizedAccountsRead:
    if not isinstance(value, FinalizedAccountsRead) or not isinstance(value.accounts, Mapping): raise SignerAuthorizationError("finalized_accounts_read_invalid")
    _slot(value.context_slot, "finalized_accounts_context_slot", minimum)
    if set(value.accounts) != {market, notary_config}: raise SignerAuthorizationError("finalized_accounts_shape_invalid")
    if any(account is not None and not isinstance(account, Account) for account in value.accounts.values()): raise SignerAuthorizationError("finalized_account_invalid")
    return value
def authorize(*, request: Mapping[str, Any], config: SignerAuthorizationConfig, rpc: FinalizedRpc, now_ms: int) -> AuthorizationResult:
    if config.signer_slot not in {"A","B"} or config.verifier_a.public_key == config.verifier_b.public_key: raise SignerAuthorizationError("signer_config_invalid")
    r=parse_request(request)
    if r["cluster_genesis_hash"] != config.expected_cluster_genesis_hash or r["program_id"] != config.expected_program_id or rpc.genesis_hash() != config.expected_cluster_genesis_hash: raise SignerAuthorizationError("genesis_or_program_mismatch")
    try:
        a=verify_attestation(r["verifier_a_attestation"], expected_public_key=config.verifier_a.public_key, expected_verifier_id=config.verifier_a.verifier_id, expected_verifier_version=config.verifier_a.verifier_version, expected_verifier_implementation_digest=config.verifier_a.implementation_digest, now_ms=now_ms)
        b=verify_attestation(r["verifier_b_attestation"], expected_public_key=config.verifier_b.public_key, expected_verifier_id=config.verifier_b.verifier_id, expected_verifier_version=config.verifier_b.verifier_version, expected_verifier_implementation_digest=config.verifier_b.implementation_digest, now_ms=now_ms)
    except VerifierAttestationError as exc: raise SignerAuthorizationError("attestation_invalid") from exc
    fields=("job_id","cluster_genesis_hash","program_id","market","resolver_definition_hash","evidence_hash","outcome","proof_hash","public_inputs_hash")
    if any(a[k]!=b[k] for k in fields) or any(a[k]!=r[k] for k in ("cluster_genesis_hash","program_id","market")): raise SignerAuthorizationError("attestation_binding_mismatch")
    binding={k:a[k] for k in ("cluster_genesis_hash","program_id","market","resolver_definition_hash","evidence_hash","proof_hash","public_inputs_hash")}
    if a["job_id"] != settlement_authorization_job_id(binding): raise SignerAuthorizationError("authorization_job_mismatch")
    finalized_floor=_slot(rpc.finalized_slot(), "finalized_slot")
    probe=_finalized_account_read(rpc.finalized_account(r["market"], min_context_slot=finalized_floor), minimum=finalized_floor)
    if probe.account is None or probe.account.owner != config.expected_program_id: raise SignerAuthorizationError("market_missing_or_owner_invalid")
    probe_market=_market(probe.account.data)
    snapshot=_finalized_accounts_read(
        rpc.finalized_accounts((r["market"], probe_market["notary_config"]), min_context_slot=max(finalized_floor, probe.context_slot)),
        market=r["market"], notary_config=probe_market["notary_config"], minimum=max(finalized_floor, probe.context_slot),
    )
    acct=snapshot.accounts[r["market"]]
    if acct is None or acct.owner != config.expected_program_id: raise SignerAuthorizationError("market_missing_or_owner_invalid")
    m=_market(acct.data)
    if m["notary_config"] != probe_market["notary_config"]: raise SignerAuthorizationError("market_notary_changed")
    expected,bump=derive_market_pda(Pubkey.from_string(m["creator"]),m["resolver_hash"],m["open_ts"],m["nonce"],Pubkey.from_string(config.expected_program_id))
    if str(expected)!=r["market"] or bump!=m["bump"]: raise SignerAuthorizationError("market_pda_invalid")
    if m["status"]==2 or m["outcome"]!=0 or m["resolved_ts"]!=0 or m["proof"]!=bytes(32) or m["inputs"]!=bytes(32) or m["resolver_hash"].hex()!=a["resolver_definition_hash"] or not m["open_ts"]<=m["lock_ts"]<=m["resolve_ts"]: raise SignerAuthorizationError("market_state_invalid")
    nacc=snapshot.accounts[m["notary_config"]]
    if nacc is None or nacc.owner!=config.expected_program_id: raise SignerAuthorizationError("notary_missing_or_owner_invalid")
    n=_notary(nacc.data); expected,bump=derive_notary_config_snapshot_pda(Pubkey.from_string(n["admin"]),n["version"],Pubkey.from_string(config.expected_program_id))
    if str(expected)!=m["notary_config"] or bump!=n["bump"] or n["threshold"]!=2 or n["count"]!=2 or set(n["keys"])!={config.own_notary_public_key,config.counterpart_notary_public_key}: raise SignerAuthorizationError("notary_state_invalid")
    block_time=_slot(rpc.block_time(snapshot.context_slot), "finalized_block_time")
    if block_time<m["resolve_ts"]: raise SignerAuthorizationError("market_not_resolvable")
    message=build_resolution_message_v2(program_id=config.expected_program_id,market=r["market"],notary_config=m["notary_config"],resolver_hash=m["resolver_hash"],open_ts=m["open_ts"],resolve_ts=m["resolve_ts"],notary_config_version=n["version"],outcome=a["outcome"],proof_hash=bytes.fromhex(a["proof_hash"]),public_inputs_hash=bytes.fromhex(a["public_inputs_hash"]))
    return AuthorizationResult(a["job_id"],r["market"],m["notary_config"],a["outcome"],message,hashlib.sha256(message).hexdigest(),config.signer_slot,config.own_notary_public_key)
