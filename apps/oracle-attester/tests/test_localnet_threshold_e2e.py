import base64
import json
import os
import sys
import time
from pathlib import Path

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.rpc.api import Client

REPO_ROOT = Path(__file__).resolve().parents[3]
SDK_ROOT = REPO_ROOT / "sdk" / "python"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from prophet_sdk import MarketOutcome, MarketStatus, ProphetClient, derive_market_pda
from prophet_sdk.resolver_hash import compute_resolver_hash
from src.attester import AttesterService
from src.config import settings
from src.types import OutcomeEnum, ResolveRequest
from src.zktls_verifier import ZkTlsVerifyResult

NATIVE_MINT = Pubkey.from_string("So11111111111111111111111111111111111111112")


class _DeterministicVerifier:
    def verify(self, *, resolver, proof_bytes: bytes, public_inputs_bytes: bytes) -> ZkTlsVerifyResult:
        if not proof_bytes:
            return ZkTlsVerifyResult(ok=False, reason="missing_proof", provider="test")
        if not public_inputs_bytes:
            return ZkTlsVerifyResult(ok=False, reason="missing_public_inputs", provider="test")
        return ZkTlsVerifyResult(ok=True, provider="test", meta={"resolver_url": resolver.url})


def _write_keypair(path: Path, kp: Keypair) -> None:
    path.write_text(json.dumps(list(bytes(kp))), encoding="utf-8")


def _airdrop(client: Client, pubkey: Pubkey, lamports: int) -> None:
    sig = client.request_airdrop(pubkey, lamports).value
    if not sig:
        raise RuntimeError(f"airdrop request failed for {pubkey}")

    for _ in range(30):
        bal = client.get_balance(pubkey).value or 0
        if bal >= lamports:
            return
        time.sleep(1)

    raise RuntimeError(f"airdrop not confirmed for {pubkey}")


def _chain_time(client: Client) -> int:
    try:
        slot = client.get_slot().value
        block_time = client.get_block_time(slot).value
        if block_time is not None:
            return int(block_time)
    except Exception:
        pass
    return int(time.time())


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("RUN_LOCALNET"), reason="Skipping localnet threshold e2e")
async def test_localnet_threshold_resolve_via_attester(tmp_path, monkeypatch):
    rpc_url = os.getenv("RPC_URL", "http://127.0.0.1:8899")
    program_id = os.getenv("PROPHET_PROGRAM_ID", "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A")

    payer = Keypair()
    relayer = Keypair()
    notary1 = Keypair()
    notary2 = Keypair()
    notary3 = Keypair()

    payer_path = tmp_path / "payer.json"
    relayer_path = tmp_path / "relayer.json"
    notary1_path = tmp_path / "notary1.json"
    notary2_path = tmp_path / "notary2.json"
    notary3_path = tmp_path / "notary3.json"
    _write_keypair(payer_path, payer)
    _write_keypair(relayer_path, relayer)
    _write_keypair(notary1_path, notary1)
    _write_keypair(notary2_path, notary2)
    _write_keypair(notary3_path, notary3)

    rpc = Client(rpc_url)
    _airdrop(rpc, payer.pubkey(), 10_000_000_000)
    _airdrop(rpc, relayer.pubkey(), 10_000_000_000)

    sdk = ProphetClient(
        rpc_url=rpc_url,
        payer_keypair_path=str(payer_path),
        program_id=program_id,
    )

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
    (resolver_store / f"{resolver_hash.hex()}.json").write_text(
        json.dumps(resolver_def),
        encoding="utf-8",
    )

    now = _chain_time(rpc)
    open_ts = now - 20
    lock_ts = now - 10
    resolve_ts = now - 5

    notary_config, _ = sdk.initialize_notary_config(
        2,
        [notary1.pubkey(), notary2.pubkey(), notary3.pubkey()],
    )
    sdk.initialize_market_v2(
        resolver_hash=resolver_hash,
        open_ts=open_ts,
        lock_ts=lock_ts,
        resolve_ts=resolve_ts,
        notary_config=notary_config,
        quote_mint=NATIVE_MINT,
    )

    market, _ = derive_market_pda(resolver_hash, open_ts, sdk.program_id)

    monkeypatch.setattr(settings, "RPC_URL", rpc_url)
    monkeypatch.setattr(settings, "PROPHET_PROGRAM_ID", program_id)
    monkeypatch.setattr(settings, "ORACLE_KEYPAIR_PATH", str(payer_path))
    monkeypatch.setattr(settings, "RELAYER_KEYPAIR_PATH", str(relayer_path))
    monkeypatch.setattr(settings, "PROOF_STORE_DIR", str(proof_store))
    monkeypatch.setattr(settings, "RESOLVER_STORE_DIR", str(resolver_store))
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "ZKTLS_MODE", "reclaim_http")
    monkeypatch.setattr(settings, "REQUIRE_ZKTLS", True)
    monkeypatch.setattr(settings, "RECLAIM_VERIFY_URL", "https://verify.example")
    monkeypatch.setattr(settings, "PROOF_FETCH_MODE", "local")
    monkeypatch.setattr(settings, "NOTARY_SIGNER_MODE", "local")
    monkeypatch.setattr(settings, "ALLOW_LOCAL_NOTARY_KEYS", True)
    monkeypatch.setattr(
        settings,
        "NOTARY_KEYPAIR_PATHS",
        ",".join(
            [
                str(notary1_path),
                str(notary2_path),
                str(notary3_path),
            ]
        ),
    )
    monkeypatch.setattr(settings, "ALLOW_LEGACY_SINGLE_ORACLE", False)

    service = AttesterService()
    service.verifier = _DeterministicVerifier()
    proof_bytes = b"localnet-threshold-proof"
    public_inputs_bytes = json.dumps({"data": {"answer": 42}}).encode("utf-8")
    req = ResolveRequest(
        market=str(market),
        outcome=OutcomeEnum.YES,
        proof_bytes_b64=base64.b64encode(proof_bytes).decode("ascii"),
        public_inputs_bytes_b64=base64.b64encode(public_inputs_bytes).decode("ascii"),
    )

    resp = await service.resolve_market(req)

    market_acc = sdk.fetch_market(market)
    assert market_acc is not None
    assert market_acc.status == MarketStatus.Resolved
    assert market_acc.outcome == MarketOutcome.Yes
    assert market_acc.proof_hash.hex() == resp.proof_hash_hex
    assert market_acc.public_inputs_hash.hex() == resp.public_inputs_hash_hex
    assert resp.signature


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("RUN_LOCALNET"), reason="Skipping localnet threshold e2e")
async def test_localnet_threshold_invalid_resolve_via_attester(tmp_path, monkeypatch):
    rpc_url = os.getenv("RPC_URL", "http://127.0.0.1:8899")
    program_id = os.getenv("PROPHET_PROGRAM_ID", "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A")

    payer = Keypair()
    relayer = Keypair()
    notary1 = Keypair()
    notary2 = Keypair()
    notary3 = Keypair()

    payer_path = tmp_path / "payer.json"
    relayer_path = tmp_path / "relayer.json"
    notary1_path = tmp_path / "notary1.json"
    notary2_path = tmp_path / "notary2.json"
    notary3_path = tmp_path / "notary3.json"
    _write_keypair(payer_path, payer)
    _write_keypair(relayer_path, relayer)
    _write_keypair(notary1_path, notary1)
    _write_keypair(notary2_path, notary2)
    _write_keypair(notary3_path, notary3)

    rpc = Client(rpc_url)
    _airdrop(rpc, payer.pubkey(), 10_000_000_000)
    _airdrop(rpc, relayer.pubkey(), 10_000_000_000)

    sdk = ProphetClient(
        rpc_url=rpc_url,
        payer_keypair_path=str(payer_path),
        program_id=program_id,
    )

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
    (resolver_store / f"{resolver_hash.hex()}.json").write_text(
        json.dumps(resolver_def),
        encoding="utf-8",
    )

    now = _chain_time(rpc)
    open_ts = now - 20
    lock_ts = now - 10
    resolve_ts = now - 5

    notary_config, _ = sdk.initialize_notary_config(
        2,
        [notary1.pubkey(), notary2.pubkey(), notary3.pubkey()],
    )
    sdk.initialize_market_v2(
        resolver_hash=resolver_hash,
        open_ts=open_ts,
        lock_ts=lock_ts,
        resolve_ts=resolve_ts,
        notary_config=notary_config,
        quote_mint=NATIVE_MINT,
    )

    market, _ = derive_market_pda(resolver_hash, open_ts, sdk.program_id)

    monkeypatch.setattr(settings, "RPC_URL", rpc_url)
    monkeypatch.setattr(settings, "PROPHET_PROGRAM_ID", program_id)
    monkeypatch.setattr(settings, "ORACLE_KEYPAIR_PATH", str(payer_path))
    monkeypatch.setattr(settings, "RELAYER_KEYPAIR_PATH", str(relayer_path))
    monkeypatch.setattr(settings, "PROOF_STORE_DIR", str(proof_store))
    monkeypatch.setattr(settings, "RESOLVER_STORE_DIR", str(resolver_store))
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "ZKTLS_MODE", "reclaim_http")
    monkeypatch.setattr(settings, "REQUIRE_ZKTLS", True)
    monkeypatch.setattr(settings, "RECLAIM_VERIFY_URL", "https://verify.example")
    monkeypatch.setattr(settings, "PROOF_FETCH_MODE", "local")
    monkeypatch.setattr(settings, "NOTARY_SIGNER_MODE", "local")
    monkeypatch.setattr(settings, "ALLOW_LOCAL_NOTARY_KEYS", True)
    monkeypatch.setattr(
        settings,
        "NOTARY_KEYPAIR_PATHS",
        ",".join(
            [
                str(notary1_path),
                str(notary2_path),
                str(notary3_path),
            ]
        ),
    )
    monkeypatch.setattr(settings, "ALLOW_LEGACY_SINGLE_ORACLE", False)

    service = AttesterService()
    service.verifier = _DeterministicVerifier()
    proof_bytes = b"localnet-threshold-proof-invalid"
    public_inputs_bytes = json.dumps({"data": {"unexpected": 7}}).encode("utf-8")
    req = ResolveRequest(
        market=str(market),
        outcome=OutcomeEnum.INVALID,
        proof_bytes_b64=base64.b64encode(proof_bytes).decode("ascii"),
        public_inputs_bytes_b64=base64.b64encode(public_inputs_bytes).decode("ascii"),
    )

    resp = await service.resolve_market(req)

    market_acc = sdk.fetch_market(market)
    assert market_acc is not None
    assert market_acc.status == MarketStatus.Resolved
    assert market_acc.outcome == MarketOutcome.Invalid
    assert market_acc.proof_hash.hex() == resp.proof_hash_hex
    assert market_acc.public_inputs_hash.hex() == resp.public_inputs_hash_hex
    assert resp.signature
