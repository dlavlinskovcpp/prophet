# apps/oracle-attester/src/attester.py
import base64
import time
import logging
import struct
import os
import json
from typing import Any, List, Optional, Dict, Tuple

import httpx
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from cachetools import TTLCache

from .audit import JsonlAuditLogger
from .solana_client import SolanaClient
from .types import ResolveRequest, ResolveResponse, OutcomeEnum
from .config import settings
from .resolver import ResolverDefinition, evaluate_resolver
from .resolver_registry import make_resolver_registry
from .zktls_verifier import make_verifier
from .proof_fetcher import make_fetcher

logger = logging.getLogger(__name__)

OUTCOME_MAP = {
    OutcomeEnum.YES: 1,
    OutcomeEnum.NO: 2,
    OutcomeEnum.INVALID: 3,
}

DOMAIN_V2 = b"PROPHET_RESOLVE_V2"


def _load_keypair(path_or_str: str) -> Keypair:
    """Load a Solana Ed25519 keypair from:
    - a JSON file path containing a [u8;64] array
    - an inline JSON array string
    - a comma-separated list of ints
    - a base58-encoded private key (solders)
    """
    val = (path_or_str or "").strip()
    if not val:
        raise ValueError("Empty keypair path")

    if os.path.exists(val):
        with open(val, "r") as f:
            val = f.read().strip()

    kp: Optional[Keypair] = None

    if val.startswith("[") and val.endswith("]"):
        try:
            int_list = json.loads(val)
            kp = Keypair.from_bytes(bytes(int_list))
        except Exception:
            kp = None
    elif "," in val and not val.startswith("["):
        try:
            int_list = [int(x) for x in val.split(",") if x.strip()]
            kp = Keypair.from_bytes(bytes(int_list))
        except Exception:
            kp = None

    if kp is None:
        try:
            kp = Keypair.from_base58_string(val)
        except Exception as e:
            raise ValueError(f"Failed to parse keypair: {e}")

    return kp


def _load_notary_keypairs_from_config() -> List[Keypair]:
    """Loads local notary keypairs for threshold mode.

    Config:
      - NOTARY_KEYPAIR_PATHS: comma-separated list of file paths or inline keypair strings.
        If empty, falls back to ORACLE_KEYPAIR_PATH for local/dev compatibility.
    """
    raw = (settings.NOTARY_KEYPAIR_PATHS or "").strip()
    paths: List[str]
    if raw:
        paths = [p.strip() for p in raw.split(",") if p.strip()]
    else:
        paths = [settings.ORACLE_KEYPAIR_PATH]

    kps: List[Keypair] = []
    for p in paths:
        try:
            kps.append(_load_keypair(p))
        except Exception as e:
            logger.warning(f"Failed to load notary keypair from '{p}': {e}")
    return kps


class RemoteNotarySigner:
    """HTTP remote signer adapter.

    Expected request:
      POST REMOTE_SIGNER_URL
      { "public_key": "<base58>", "message_b64": "<base64>", "context": {...} }

    Expected response:
      { "signature_b64": "<base64(64 bytes)>", "public_key": "<optional echo>" }
    """

    def __init__(self, url: str, api_key: str, timeout_s: float):
        self.url = url
        self.api_key = api_key
        self.timeout_s = timeout_s

    def sign(self, pubkey: Pubkey, message: bytes, context: Dict[str, str]) -> bytes:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body = {
            "public_key": str(pubkey),
            "message_b64": base64.b64encode(message).decode("ascii"),
            "context": context,
        }

        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                resp = client.post(self.url, json=body, headers=headers)
        except Exception as e:
            raise RuntimeError(f"remote signer request failed: {e}")

        if resp.status_code >= 300:
            raise RuntimeError(f"remote signer returned {resp.status_code}: {resp.text[:200]}")

        try:
            payload = resp.json()
        except Exception as e:
            raise RuntimeError(f"remote signer returned invalid JSON: {e}")

        sig_b64 = str(payload.get("signature_b64", "")).strip()
        if not sig_b64:
            raise RuntimeError("remote signer response missing signature_b64")

        try:
            sig = base64.b64decode(sig_b64, validate=True)
        except Exception as e:
            raise RuntimeError(f"remote signer signature is not valid base64: {e}")

        if len(sig) != 64:
            raise RuntimeError(f"remote signer signature length invalid: {len(sig)}")

        echoed_pk = str(payload.get("public_key", "")).strip()
        if echoed_pk and echoed_pk != str(pubkey):
            raise RuntimeError("remote signer returned signature for unexpected public key")

        return sig


class AttesterService:
    def __init__(self):
        self.client = SolanaClient()
        self.inflight_cache = TTLCache(maxsize=1000, ttl=60)
        self.resolved_cache = TTLCache(maxsize=1000, ttl=600)
        self.verifier = make_verifier()
        self.fetcher = make_fetcher()
        self.resolver_registry = make_resolver_registry()
        self.audit_log = JsonlAuditLogger(
            settings.ATTESTER_AUDIT_LOG_PATH,
            "oracle-attester",
        )
        self.notary_signer_mode = (settings.NOTARY_SIGNER_MODE or "remote").strip().lower()
        self.remote_notary_signer = (
            RemoteNotarySigner(
                url=settings.REMOTE_SIGNER_URL,
                api_key=settings.REMOTE_SIGNER_API_KEY,
                timeout_s=settings.REMOTE_SIGNER_TIMEOUT_S,
            )
            if self.notary_signer_mode == "remote"
            else None
        )

    def _enforce_resolution_mode_policy(self, state: Dict[str, Any]) -> None:
        if state.get("notary_config", Pubkey.default()) != Pubkey.default():
            return
        raise PermissionError(
            "Legacy single-oracle markets are no longer supported. "
            "Create and resolve v2 markets with a notary_config."
        )

    def _load_resolver(self, resolver_hash: bytes) -> ResolverDefinition:
        return self.resolver_registry.load(resolver_hash)

    def _build_message_v2(
        self,
        market_pubkey: Pubkey,
        notary_config_pubkey: Pubkey,
        resolver_hash: bytes,
        open_ts: int,
        resolve_ts: int,
        notary_config_version: int,
        outcome_idx: int,
        proof_hash: bytes,
        public_inputs_hash: bytes,
    ) -> bytes:
        return (
            DOMAIN_V2
            + bytes(self.client.program_id)
            + bytes(market_pubkey)
            + bytes(notary_config_pubkey)
            + resolver_hash
            + struct.pack("<q", open_ts)
            + struct.pack("<q", resolve_ts)
            + struct.pack("<Q", notary_config_version)
            + struct.pack("B", outcome_idx)
            + proof_hash
            + public_inputs_hash
        )

    async def resolve_market(self, req: ResolveRequest) -> ResolveResponse:
        market_str = str(req.market)
        market_pubkey = Pubkey.from_string(market_str)
        state: Optional[Dict[str, Any]] = None
        proof_hash = bytes(32)
        pi_hash = bytes(32)
        verify_provider = ""
        verify_ok = False
        verify_reason = ""
        threshold_mode = False

        audit_base: Dict[str, Any] = {
            "market": market_str,
            "requested_outcome": str(req.outcome),
            "notary_signer_mode": self.notary_signer_mode,
            "resolver_registry_mode": self.resolver_registry.health().get("mode", "unknown"),
        }

        try:
            # 1) Fetch Chain State
            state = self.client.get_market_state_full(market_pubkey)
            if state is None:
                raise LookupError(f"Market {req.market} not found")

            audit_base.update(
                {
                    "resolver_hash": state["resolver_hash"].hex(),
                    "notary_config": str(state.get("notary_config", Pubkey.default())),
                    "resolve_ts": int(state["resolve_ts"]),
                }
            )

            # status == 2 => Resolved (per program enum order)
            if state["status"] == 2:
                raise ValueError("Market is already resolved (on-chain)")
            if market_str in self.inflight_cache:
                raise ValueError("Market resolution in progress (in-flight)")
            self._enforce_resolution_mode_policy(state)

            chain_time = self.client.get_chain_time()
            if chain_time < state["resolve_ts"]:
                raise ValueError("Market not resolvable yet.")

            # Decode Inputs Early (direct payloads and/or proof_ref fetch)
            pi_bytes = base64.b64decode(req.public_inputs_bytes_b64) if req.public_inputs_bytes_b64 else b""
            proof_bytes = base64.b64decode(req.proof_bytes_b64) if req.proof_bytes_b64 else b""
            proof_ref = (req.proof_ref or "").strip()

            if proof_ref and (not proof_bytes or not pi_bytes):
                try:
                    fetched = self.fetcher.fetch(proof_ref)
                    if not proof_bytes:
                        proof_bytes = fetched.proof_bytes
                    if not pi_bytes:
                        pi_bytes = fetched.public_inputs_bytes
                    logger.info(
                        f"Fetched proof via ref provider={fetched.provider} "
                        f"proof_len={len(proof_bytes)} pi_len={len(pi_bytes)}"
                    )
                except Exception as e:
                    raise ValueError(f"Failed to fetch proof_ref: {e}")

            # Compute hashes early for logging
            proof_hash = self.client.sha256_digest(proof_bytes)
            pi_hash = self.client.sha256_digest(pi_bytes)

            # 2) Deterministic Verification (Logic)
            try:
                resolver_def = self._load_resolver(state["resolver_hash"])

                if not pi_bytes:
                    computed_outcome = OutcomeEnum.INVALID
                else:
                    try:
                        public_inputs = json.loads(pi_bytes)
                        if not isinstance(public_inputs, dict) or not public_inputs:
                            computed_outcome = OutcomeEnum.INVALID
                        else:
                            computed_outcome = evaluate_resolver(resolver_def, public_inputs)
                    except json.JSONDecodeError:
                        computed_outcome = OutcomeEnum.INVALID

                if computed_outcome != req.outcome:
                    raise ValueError(
                        f"Outcome mismatch: Computed {computed_outcome} but received request for {req.outcome}"
                    )
            except ValueError:
                raise
            except Exception as e:
                logger.error(f"Verification system error: {e}")
                raise ValueError(f"Verification failed: {e}")

            # 3) zkTLS Verification (Provider)
            verify_res = self.verifier.verify(
                resolver=resolver_def, proof_bytes=proof_bytes, public_inputs_bytes=pi_bytes
            )
            verify_provider = verify_res.provider
            verify_ok = verify_res.ok
            verify_reason = verify_res.reason or ""

            self.audit_log.write(
                "resolve_verified",
                {
                    **audit_base,
                    "computed_outcome": str(computed_outcome),
                    "proof_hash": proof_hash.hex(),
                    "public_inputs_hash": pi_hash.hex(),
                    "proof_len": len(proof_bytes),
                    "public_inputs_len": len(pi_bytes),
                    "proof_ref": proof_ref,
                    "zktls_mode": settings.ZKTLS_MODE,
                    "require_zktls": settings.REQUIRE_ZKTLS,
                    "zktls_provider": verify_provider,
                    "zktls_ok": verify_ok,
                    "zktls_reason": verify_reason,
                },
            )

            logger.info(
                f"AUDIT_RESOLVE: market={market_str} "
                f"resolver={state['resolver_hash'].hex()} "
                f"computed={computed_outcome} req={req.outcome} "
                f"zktls_mode={settings.ZKTLS_MODE} require={settings.REQUIRE_ZKTLS} "
                f"provider={verify_provider} ok={verify_ok} reason={verify_reason} "
                f"proof_len={len(proof_bytes)} pi_len={len(pi_bytes)} "
                f"proof_hash={proof_hash.hex()} pi_hash={pi_hash.hex()} "
                f"notary_config={str(state.get('notary_config', Pubkey.default()))}"
            )

            if settings.REQUIRE_ZKTLS and not verify_ok:
                raise ValueError(f"zkTLS verification failed: {verify_reason}")
            if not verify_ok:
                logger.warning(
                    "zkTLS verification failed but REQUIRE_ZKTLS=False. "
                    f"Proceeding. Reason: {verify_reason}"
                )

            # 4) Proceed to Sign + Submit
            self.inflight_cache[market_str] = True

            outcome_idx = OUTCOME_MAP[req.outcome]

            # Persist proofs for audit/debugging
            try:
                os.makedirs(settings.PROOF_STORE_DIR, exist_ok=True)
                proof_file = os.path.join(
                    settings.PROOF_STORE_DIR, f"{market_str}_{proof_hash.hex()}_proof.bin"
                )
                pi_file = os.path.join(
                    settings.PROOF_STORE_DIR, f"{market_str}_{pi_hash.hex()}_public_inputs.bin"
                )
                with open(proof_file, "wb") as f:
                    f.write(proof_bytes)
                with open(pi_file, "wb") as f:
                    f.write(pi_bytes)
            except Exception as e:
                logger.warning(f"Failed to persist proofs: {e}")

            notary_cfg_pk: Pubkey = state.get("notary_config", Pubkey.default())
            threshold_mode = notary_cfg_pk != Pubkey.default()

            if threshold_mode:
                # --- Threshold flow (t-of-n) ---
                cfg = self.client.get_notary_config(notary_cfg_pk)
                if cfg is None:
                    raise LookupError(f"NotaryConfig {str(notary_cfg_pk)} not found")

                msg = self._build_message_v2(
                    market_pubkey=market_pubkey,
                    notary_config_pubkey=notary_cfg_pk,
                    resolver_hash=state["resolver_hash"],
                    open_ts=state["open_ts"],
                    resolve_ts=state["resolve_ts"],
                    notary_config_version=int(cfg["version"]),
                    outcome_idx=outcome_idx,
                    proof_hash=proof_hash,
                    public_inputs_hash=pi_hash,
                )

                threshold = int(cfg["threshold"])
                allowed_sorted = sorted(list(cfg["notary_keys"]), key=lambda pk: bytes(pk))
                ed25519_ixs = []

                if self.notary_signer_mode == "remote":
                    if self.remote_notary_signer is None:
                        raise RuntimeError("remote notary signer is not configured")

                    signed_count = 0
                    for pk in allowed_sorted:
                        if signed_count >= threshold:
                            break
                        try:
                            sig_bytes = self.remote_notary_signer.sign(
                                pubkey=pk,
                                message=msg,
                                context={
                                    "market": market_str,
                                    "notary_config": str(notary_cfg_pk),
                                    "notary_config_version": str(int(cfg["version"])),
                                    "outcome_idx": str(outcome_idx),
                                    "proof_hash": proof_hash.hex(),
                                    "public_inputs_hash": pi_hash.hex(),
                                },
                            )
                            ed25519_ixs.append(self.client.build_ed25519_ix(msg, sig_bytes, bytes(pk)))
                            signed_count += 1
                        except Exception as e:
                            logger.warning(f"Remote signer failed for notary {str(pk)}: {e}")

                    if signed_count < threshold:
                        raise PermissionError(
                            f"Not enough remote notary signatures. Have {signed_count}, need {threshold}"
                        )

                    payer = self.client.relayer_kp or self.client.oracle_kp
                else:
                    local_kps = _load_notary_keypairs_from_config()
                    local_by_pk: Dict[Pubkey, Keypair] = {kp.pubkey(): kp for kp in local_kps}
                    eligible: List[Keypair] = [local_by_pk[pk] for pk in allowed_sorted if pk in local_by_pk]

                    if len(eligible) < threshold:
                        raise PermissionError(
                            f"Not enough local notary keys. Have {len(eligible)} eligible, need {threshold}"
                        )

                    eligible.sort(key=lambda k: bytes(k.pubkey()))
                    chosen = eligible[:threshold]

                    for kp in chosen:
                        sig_obj = kp.sign_message(msg)
                        sig_bytes = bytes(sig_obj)
                        ed25519_ixs.append(
                            self.client.build_ed25519_ix(msg, sig_bytes, bytes(kp.pubkey()))
                        )

                    payer = self.client.relayer_kp or chosen[0]

                if payer is None:
                    raise PermissionError("No payer available for threshold resolve transaction")

                resolve_ix = self.client.build_resolve_threshold_ix(
                    market=market_pubkey,
                    notary_config=notary_cfg_pk,
                    outcome_idx=outcome_idx,
                    proof_hash=proof_hash,
                    public_inputs_hash=pi_hash,
                )

                sig = self.client.submit_and_confirm(ed25519_ixs + [resolve_ix], payer)

            else:
                raise PermissionError(
                    "Legacy single-oracle markets are no longer supported. "
                    "Create and resolve v2 markets with a notary_config."
                )

            final_state = self.client.get_market_state_full(market_pubkey)
            if final_state and final_state["status"] == 2:
                self.resolved_cache[market_str] = True
                if market_str in self.inflight_cache:
                    del self.inflight_cache[market_str]
                self.audit_log.write(
                    "resolve_submitted",
                    {
                        **audit_base,
                        "signature": sig,
                        "threshold_mode": threshold_mode,
                        "proof_hash": proof_hash.hex(),
                        "public_inputs_hash": pi_hash.hex(),
                        "resolved_ts": int(final_state["resolved_ts"]),
                    },
                )
                return ResolveResponse(
                    signature=sig,
                    proof_hash_hex=proof_hash.hex(),
                    public_inputs_hash_hex=pi_hash.hex(),
                    resolved_ts=final_state["resolved_ts"],
                )
            raise RuntimeError("Tx confirmed but market status not Resolved")
        except Exception as e:
            if market_str in self.inflight_cache:
                del self.inflight_cache[market_str]
            failure_payload = {
                **audit_base,
                "reason": str(e),
                "threshold_mode": threshold_mode,
                "proof_hash": proof_hash.hex(),
                "public_inputs_hash": pi_hash.hex(),
                "zktls_provider": verify_provider,
                "zktls_ok": verify_ok,
                "zktls_reason": verify_reason,
            }
            if state is not None:
                failure_payload["status"] = int(state["status"])
            self.audit_log.write("resolve_failed", failure_payload)
            raise


_service_instance: Optional[AttesterService] = None


def get_service() -> AttesterService:
    global _service_instance
    if _service_instance is None:
        _service_instance = AttesterService()
    return _service_instance


class _ServiceProxy:
    """Lazy proxy to avoid runtime setup at import-time in tests."""

    def __getattr__(self, item: str) -> Any:
        return getattr(get_service(), item)


service = _ServiceProxy()
