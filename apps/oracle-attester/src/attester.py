# apps/oracle-attester/src/attester.py
import base64
import time
import logging
import struct
import os
import json
from typing import List, Optional, Dict, Tuple

from solders.pubkey import Pubkey
from solders.keypair import Keypair
from cachetools import TTLCache

from .solana_client import SolanaClient
from .types import ResolveRequest, ResolveResponse, OutcomeEnum
from .config import settings
from .resolver import ResolverDefinition, evaluate_resolver
from .zktls_verifier import make_verifier
from .proof_fetcher import make_fetcher

logger = logging.getLogger(__name__)

OUTCOME_MAP = {
    OutcomeEnum.YES: 1,
    OutcomeEnum.NO: 2,
    OutcomeEnum.INVALID: 3,
}

DOMAIN_V1 = b"PROPHET_RESOLVE_V1"
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


def _load_notary_keypairs_from_env() -> List[Keypair]:
    """Loads notary keypairs for threshold mode.

    Env:
      - NOTARY_KEYPAIR_PATHS: comma-separated list of file paths or inline keypair strings.
        If missing, falls back to ORACLE_KEYPAIR_PATH (single key) to keep local dev simple.
    """
    raw = os.getenv("NOTARY_KEYPAIR_PATHS", "").strip()
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


class AttesterService:
    def __init__(self):
        self.client = SolanaClient()
        self.inflight_cache = TTLCache(maxsize=1000, ttl=60)
        self.resolved_cache = TTLCache(maxsize=1000, ttl=600)
        self.verifier = make_verifier()
        self.fetcher = make_fetcher()

    def _load_resolver(self, resolver_hash: bytes) -> ResolverDefinition:
        hash_hex = resolver_hash.hex()
        path = os.path.join(settings.RESOLVER_STORE_DIR, f"{hash_hex}.json")

        if not os.path.exists(path):
            raise ValueError(f"Resolver definition not found for hash: {hash_hex}")

        with open(path, "r") as f:
            data = json.load(f)
            from .resolver import compute_resolver_hash

            if compute_resolver_hash(data) != resolver_hash:
                raise ValueError(f"Integrity check failed for resolver {hash_hex}")
            return ResolverDefinition(**data)

    def _build_message_v1(
        self,
        market_pubkey: Pubkey,
        resolver_hash: bytes,
        open_ts: int,
        outcome_idx: int,
        proof_hash: bytes,
        public_inputs_hash: bytes,
    ) -> bytes:
        return (
            DOMAIN_V1
            + bytes(market_pubkey)
            + resolver_hash
            + struct.pack("<q", open_ts)
            + struct.pack("B", outcome_idx)
            + proof_hash
            + public_inputs_hash
        )

    def _build_message_v2(
        self,
        market_pubkey: Pubkey,
        notary_config_pubkey: Pubkey,
        resolver_hash: bytes,
        open_ts: int,
        resolve_ts: int,
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
            + struct.pack("B", outcome_idx)
            + proof_hash
            + public_inputs_hash
        )

    async def resolve_market(self, req: ResolveRequest) -> ResolveResponse:
        market_str = str(req.market)
        market_pubkey = Pubkey.from_string(market_str)

        # 1) Fetch Chain State
        state = self.client.get_market_state_full(market_pubkey)
        if state is None:
            raise LookupError(f"Market {req.market} not found")

        # status == 2 => Resolved (per program enum order)
        if state["status"] == 2:
            raise ValueError("Market is already resolved (on-chain)")
        if market_str in self.inflight_cache:
            raise ValueError("Market resolution in progress (in-flight)")

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

        logger.info(
            f"AUDIT_RESOLVE: market={market_str} "
            f"resolver={state['resolver_hash'].hex()} "
            f"computed={computed_outcome} req={req.outcome} "
            f"zktls_mode={settings.ZKTLS_MODE} require={settings.REQUIRE_ZKTLS} "
            f"provider={verify_res.provider} ok={verify_res.ok} reason={verify_res.reason} "
            f"proof_len={len(proof_bytes)} pi_len={len(pi_bytes)} "
            f"proof_hash={proof_hash.hex()} pi_hash={pi_hash.hex()} "
            f"notary_config={str(state.get('notary_config', Pubkey.default()))}"
        )

        if settings.REQUIRE_ZKTLS and not verify_res.ok:
            raise ValueError(f"zkTLS verification failed: {verify_res.reason}")
        elif not verify_res.ok:
            logger.warning(
                f"zkTLS verification failed but REQUIRE_ZKTLS=False. Proceeding. Reason: {verify_res.reason}"
            )

        # 4) Proceed to Sign + Submit
        self.inflight_cache[market_str] = True

        try:
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

                # Load local notaries (for now: local file-based). This is intentionally simple for MVP.
                local_kps = _load_notary_keypairs_from_env()
                local_by_pk: Dict[Pubkey, Keypair] = {kp.pubkey(): kp for kp in local_kps}

                allowed = set(cfg["notary_keys"])
                eligible: List[Keypair] = [kp for pk, kp in local_by_pk.items() if pk in allowed]

                if len(eligible) < int(cfg["threshold"]):
                    raise PermissionError(
                        f"Not enough local notary keys. Have {len(eligible)} eligible, need {cfg['threshold']}"
                    )

                # Use first `threshold` keys (deterministic ordering by pubkey bytes for reproducibility)
                eligible.sort(key=lambda k: bytes(k.pubkey()))
                chosen = eligible[: int(cfg["threshold"])]

                msg = self._build_message_v2(
                    market_pubkey=market_pubkey,
                    notary_config_pubkey=notary_cfg_pk,
                    resolver_hash=state["resolver_hash"],
                    open_ts=state["open_ts"],
                    resolve_ts=state["resolve_ts"],
                    outcome_idx=outcome_idx,
                    proof_hash=proof_hash,
                    public_inputs_hash=pi_hash,
                )

                ed25519_ixs = []
                for kp in chosen:
                    sig_obj = kp.sign_message(msg)
                    sig_bytes = bytes(sig_obj)
                    ed25519_ixs.append(
                        self.client.build_ed25519_ix(msg, sig_bytes, bytes(kp.pubkey()))
                    )

                resolve_ix = self.client.build_resolve_threshold_ix(
                    market=market_pubkey,
                    notary_config=notary_cfg_pk,
                    outcome_idx=outcome_idx,
                    proof_hash=proof_hash,
                    public_inputs_hash=pi_hash,
                )

                payer = self.client.relayer_kp or chosen[0]
                sig = self.client.submit_and_confirm(ed25519_ixs + [resolve_ix], payer)

            else:
                # --- Legacy single-oracle flow (backward compatible) ---
                if state["oracle_authority"] != self.client.oracle_kp.pubkey():
                    raise PermissionError("Oracle mismatch.")

                msg = self._build_message_v1(
                    market_pubkey=market_pubkey,
                    resolver_hash=state["resolver_hash"],
                    open_ts=state["open_ts"],
                    outcome_idx=outcome_idx,
                    proof_hash=proof_hash,
                    public_inputs_hash=pi_hash,
                )

                if self.client.relayer_kp:
                    sig_obj = self.client.oracle_kp.sign_message(msg)
                    sig_bytes = bytes(sig_obj)
                    ed25519_ix = self.client.build_ed25519_ix(msg, sig_bytes, bytes(self.client.oracle_kp.pubkey()))
                    resolve_ix = self.client.build_resolve_signed_ix(
                        market_pubkey, outcome_idx, proof_hash, pi_hash, sig_bytes
                    )
                    sig = self.client.submit_and_confirm([ed25519_ix, resolve_ix], self.client.relayer_kp)
                else:
                    ix = self.client.build_resolve_ix(market_pubkey, outcome_idx, proof_hash, pi_hash)
                    sig = self.client.submit_and_confirm([ix], self.client.oracle_kp)

            final_state = self.client.get_market_state_full(market_pubkey)
            if final_state and final_state["status"] == 2:
                self.resolved_cache[market_str] = True
                if market_str in self.inflight_cache:
                    del self.inflight_cache[market_str]
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
            raise e


service = AttesterService()
