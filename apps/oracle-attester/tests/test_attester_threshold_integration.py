import base64
import hashlib
import json
from pathlib import Path

import pytest
from cachetools import TTLCache
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from src.attester import AttesterService
from src.config import settings
from src.resolver import compute_resolver_hash
from src.types import OutcomeEnum, ResolveRequest
from src.zktls_verifier import ZkTlsVerifyResult


class _FakeVerifier:
    def verify(self, *, resolver, proof_bytes: bytes, public_inputs_bytes: bytes) -> ZkTlsVerifyResult:
        return ZkTlsVerifyResult(ok=True, provider="mock", meta={"resolver_url": resolver.url})


class _FakeRemoteSigner:
    def __init__(self):
        self.calls = []

    def sign(self, pubkey: Pubkey, message: bytes, context: dict) -> bytes:
        self.calls.append(
            {
                "pubkey": pubkey,
                "message": message,
                "context": context,
            }
        )
        return bytes([len(self.calls)]) * 64


class _FakeSolanaClient:
    def __init__(
        self,
        *,
        program_id: Pubkey,
        market: Pubkey,
        notary_config: Pubkey,
        resolver_hash: bytes,
        open_ts: int,
        resolve_ts: int,
        version: int,
        threshold: int,
        notary_keys,
        payer: Keypair,
    ):
        self.program_id = program_id
        self.market = market
        self.notary_config = notary_config
        self.resolver_hash = resolver_hash
        self.open_ts = open_ts
        self.resolve_ts = resolve_ts
        self.version = version
        self.threshold = threshold
        self.notary_keys = list(notary_keys)
        self.relayer_kp = payer
        self.oracle_kp = Keypair()
        self._resolved = False
        self._resolved_ts = 0
        self._proof_hash = bytes(32)
        self._public_inputs_hash = bytes(32)
        self.submitted_ixs = []
        self.submitted_payer = None

    def get_market_state_full(self, market: Pubkey):
        assert market == self.market
        return {
            "status": 2 if self._resolved else 0,
            "notary_config": self.notary_config,
            "resolver_hash": self.resolver_hash,
            "open_ts": self.open_ts,
            "lock_ts": self.open_ts,
            "resolve_ts": self.resolve_ts,
            "resolved_ts": self._resolved_ts,
            "oracle_authority": self.oracle_kp.pubkey(),
            "proof_hash": self._proof_hash,
            "public_inputs_hash": self._public_inputs_hash,
        }

    def get_chain_time(self) -> int:
        return self.resolve_ts + 5

    def get_notary_config(self, cfg_pubkey: Pubkey):
        assert cfg_pubkey == self.notary_config
        return {
            "threshold": self.threshold,
            "version": self.version,
            "notary_keys": self.notary_keys,
        }

    def sha256_digest(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def build_ed25519_ix(self, msg: bytes, sig: bytes, pk: bytes):
        return {"kind": "ed25519", "msg": msg, "sig": sig, "pk": pk}

    def build_resolve_threshold_ix(
        self,
        *,
        market: Pubkey,
        notary_config: Pubkey,
        outcome_idx: int,
        proof_hash: bytes,
        public_inputs_hash: bytes,
    ):
        return {
            "kind": "resolve_threshold",
            "market": market,
            "notary_config": notary_config,
            "outcome_idx": outcome_idx,
            "proof_hash": proof_hash,
            "public_inputs_hash": public_inputs_hash,
        }

    def submit_and_confirm(self, ixs, payer: Keypair) -> str:
        self.submitted_ixs = list(ixs)
        self.submitted_payer = payer
        resolve_ix = self.submitted_ixs[-1]
        self._resolved = True
        self._resolved_ts = self.resolve_ts + 6
        self._proof_hash = resolve_ix["proof_hash"]
        self._public_inputs_hash = resolve_ix["public_inputs_hash"]
        return "sig-threshold-123"


def _make_service(*, client, verifier, remote_signer) -> AttesterService:
    svc = object.__new__(AttesterService)
    svc.client = client
    svc.inflight_cache = TTLCache(maxsize=1000, ttl=60)
    svc.resolved_cache = TTLCache(maxsize=1000, ttl=600)
    svc.verifier = verifier
    svc.fetcher = object()
    svc.notary_signer_mode = "remote"
    svc.remote_notary_signer = remote_signer
    return svc


@pytest.mark.asyncio
async def test_attester_resolves_threshold_market_via_remote_signer(tmp_path, monkeypatch):
    resolver_def = {
        "url": "https://example.test/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }
    resolver_hash = compute_resolver_hash(resolver_def)
    resolver_store = tmp_path / "resolver_store"
    proof_store = tmp_path / "proof_store"
    resolver_store.mkdir()
    proof_store.mkdir()
    (resolver_store / f"{resolver_hash.hex()}.json").write_text(json.dumps(resolver_def), encoding="utf-8")

    monkeypatch.setattr(settings, "RESOLVER_STORE_DIR", str(resolver_store))
    monkeypatch.setattr(settings, "PROOF_STORE_DIR", str(proof_store))
    monkeypatch.setattr(settings, "ALLOW_LEGACY_SINGLE_ORACLE", False)
    monkeypatch.setattr(settings, "REQUIRE_ZKTLS", True)

    program_id = Pubkey.new_unique()
    market = Pubkey.new_unique()
    notary_config = Pubkey.new_unique()
    payer = Keypair()
    notary1 = Keypair()
    notary2 = Keypair()
    notary3 = Keypair()

    fake_client = _FakeSolanaClient(
        program_id=program_id,
        market=market,
        notary_config=notary_config,
        resolver_hash=resolver_hash,
        open_ts=1_700_000_000,
        resolve_ts=1_700_000_120,
        version=7,
        threshold=2,
        notary_keys=[notary3.pubkey(), notary1.pubkey(), notary2.pubkey()],
        payer=payer,
    )
    remote_signer = _FakeRemoteSigner()
    svc = _make_service(client=fake_client, verifier=_FakeVerifier(), remote_signer=remote_signer)

    proof_bytes = b"proof-bytes"
    public_inputs_bytes = json.dumps({"data": {"answer": 42}}).encode("utf-8")
    req = ResolveRequest(
        market=str(market),
        outcome=OutcomeEnum.YES,
        proof_bytes_b64=base64.b64encode(proof_bytes).decode("ascii"),
        public_inputs_bytes_b64=base64.b64encode(public_inputs_bytes).decode("ascii"),
    )

    resp = await svc.resolve_market(req)

    expected_proof_hash = hashlib.sha256(proof_bytes).digest()
    expected_pi_hash = hashlib.sha256(public_inputs_bytes).digest()
    expected_notaries = sorted(
        [notary1.pubkey(), notary2.pubkey(), notary3.pubkey()],
        key=lambda pk: bytes(pk),
    )[:2]

    assert resp.signature == "sig-threshold-123"
    assert resp.proof_hash_hex == expected_proof_hash.hex()
    assert resp.public_inputs_hash_hex == expected_pi_hash.hex()
    assert resp.resolved_ts == fake_client._resolved_ts

    assert [call["pubkey"] for call in remote_signer.calls] == expected_notaries
    assert all(call["context"]["market"] == str(market) for call in remote_signer.calls)
    assert all(call["context"]["notary_config"] == str(notary_config) for call in remote_signer.calls)

    assert fake_client.submitted_payer == payer
    assert len(fake_client.submitted_ixs) == 3
    assert fake_client.submitted_ixs[-1]["kind"] == "resolve_threshold"
    assert fake_client.submitted_ixs[-1]["proof_hash"] == expected_proof_hash
    assert fake_client.submitted_ixs[-1]["public_inputs_hash"] == expected_pi_hash

    proof_files = list(Path(proof_store).glob(f"{market}_*_proof.bin"))
    pi_files = list(Path(proof_store).glob(f"{market}_*_public_inputs.bin"))
    assert len(proof_files) == 1
    assert len(pi_files) == 1
