"""Create and verify the real local-validator objects used by P0C4."""
from __future__ import annotations

import hashlib
import struct
import time
from typing import Any

from solana.rpc.api import Client
from solana.rpc.commitment import Finalized
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import CreateAccountParams, create_account
from solders.transaction import VersionedTransaction
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import InitializeMintParams, initialize_mint

from prophet_sdk.client import ProphetClient
from prophet_sdk.pdas import derive_market_pda, derive_notary_config_snapshot_pda

from .localtest_chain_binding import CHAIN_BINDING_SCHEMA, LocaltestChainBindingV1
from .localtest_solana_finalized_rpc import LocaltestSolanaFinalizedRpc


class LocaltestChainBootstrapError(RuntimeError):
    pass


def _hex32(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise LocaltestChainBootstrapError(f"{name}_invalid")
    return bytes.fromhex(value)


def _send_one(client: Client, instructions: list[Instruction], signers: list[Keypair], payer: Keypair) -> str:
    try:
        latest = client.get_latest_blockhash(commitment=Finalized).value
        message = MessageV0.try_compile(payer=payer.pubkey(), instructions=instructions, address_lookup_table_accounts=[], recent_blockhash=latest.blockhash)
        transaction = VersionedTransaction(message, signers)
        simulation = client.simulate_transaction(transaction, sig_verify=True, commitment=Finalized)
        if simulation.value.err is not None:
            raise LocaltestChainBootstrapError("localtest_bootstrap_simulation_failed")
        signature = client.send_raw_transaction(bytes(transaction)).value
        client.confirm_transaction(signature, commitment=Finalized)
        return str(signature)
    except LocaltestChainBootstrapError:
        raise
    except Exception as exc:
        raise LocaltestChainBootstrapError("localtest_bootstrap_transaction_failed") from exc


def _assert_signature_success(client: Client, signature: str, code: str) -> None:
    try:
        deadline = time.monotonic() + 20
        status = None
        while time.monotonic() < deadline:
            status = client.get_signature_statuses([Signature.from_string(signature)], search_transaction_history=True).value[0]
            if status is not None:
                break
            time.sleep(0.1)
        if status is None:
            raise LocaltestChainBootstrapError(f"{code}:status_unavailable")
        if status.err is not None:
            raise LocaltestChainBootstrapError(f"{code}:{status.err}")
    except LocaltestChainBootstrapError:
        raise
    except Exception as exc:
        raise LocaltestChainBootstrapError(code) from exc


def _sdk_client(client: Client, *, payer: Keypair, program_id: Pubkey) -> ProphetClient:
    sdk = object.__new__(ProphetClient)
    sdk.client = client
    sdk.program_id = program_id
    sdk.payer = payer
    return sdk


def _market_fields(raw: bytes) -> dict[str, Any]:
    if len(raw) != 8 + 416 or raw[:8] != hashlib.sha256(b"account:Market").digest()[:8]:
        raise LocaltestChainBootstrapError("localtest_market_account_malformed")
    data = raw[8:]
    return {
        "notary_config": str(Pubkey.from_bytes(data[160:192])),
        "resolver_hash": data[192:224],
        "proof_hash": data[224:256],
        "public_inputs_hash": data[256:288],
        "open_ts": struct.unpack_from("<q", data, 288)[0],
        "lock_ts": struct.unpack_from("<q", data, 296)[0],
        "resolve_ts": struct.unpack_from("<q", data, 304)[0],
        "resolved_ts": struct.unpack_from("<q", data, 312)[0],
        "status": data[371],
        "outcome": data[372],
        "bump": data[373],
        "creator": str(Pubkey.from_bytes(data[375:407])),
        "market_nonce": struct.unpack_from("<Q", data, 407)[0],
    }


def _notary_fields(raw: bytes) -> dict[str, Any]:
    if len(raw) != 8 + 48 + 32 * 32 or raw[:8] != hashlib.sha256(b"account:NotaryConfig").digest()[:8]:
        raise LocaltestChainBootstrapError("localtest_notary_account_malformed")
    data = raw[8:]
    count = data[33]
    if count > 32:
        raise LocaltestChainBootstrapError("localtest_notary_account_malformed")
    return {"admin": str(Pubkey.from_bytes(data[:32])), "threshold": data[32], "count": count, "bump": data[34], "version": struct.unpack_from("<Q", data, 40)[0], "keys": [str(Pubkey.from_bytes(data[48 + i * 32:80 + i * 32])) for i in range(count)]}


def _wait_for_resolve_time(rpc: LocaltestSolanaFinalizedRpc, resolve_ts: int, timeout_seconds: float = 90.0) -> tuple[int, int]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        slot = rpc.finalized_slot()
        block_time = rpc.block_time(slot)
        if block_time is not None and block_time >= resolve_ts:
            return slot, block_time
        time.sleep(0.15)
    raise LocaltestChainBootstrapError("localtest_resolve_time_timeout")


def bootstrap_localtest_chain(
    *,
    rpc_url: str,
    program_id: str,
    signer_a_public_key: str,
    signer_b_public_key: str,
    fee_payer: Keypair,
    resolver_definition_hash: str,
    evidence_hash: str,
    proof_hash: str,
    public_inputs_hash: str,
    outcome: str = "YES",
    market_nonce: int = 0,
    wait_for_resolve: bool = True,
) -> LocaltestChainBindingV1:
    """Bootstrap a 2/2 notary and unresolved market using public A/B keys only."""
    if not isinstance(fee_payer, Keypair):
        raise LocaltestChainBootstrapError("localtest_fee_payer_required")
    try:
        pid = Pubkey.from_string(program_id)
        a = str(Pubkey.from_string(signer_a_public_key))
        b = str(Pubkey.from_string(signer_b_public_key))
        if a == b:
            raise ValueError
        resolver = _hex32(resolver_definition_hash, "resolver_definition_hash")
        _hex32(evidence_hash, "evidence_hash")
        proof = _hex32(proof_hash, "proof_hash")
        inputs = _hex32(public_inputs_hash, "public_inputs_hash")
        if outcome not in {"YES", "NO", "INVALID"}:
            raise ValueError
        if isinstance(market_nonce, bool) or not isinstance(market_nonce, int) or not 0 <= market_nonce < 1 << 64:
            raise ValueError
    except LocaltestChainBootstrapError:
        raise
    except Exception as exc:
        raise LocaltestChainBootstrapError("localtest_bootstrap_input_invalid") from exc

    rpc = LocaltestSolanaFinalizedRpc(rpc_url, environment="localtest", mode="test", topology_classification="FUNCTIONAL_TEST_ONLY")
    client = rpc.client
    genesis = rpc.genesis_hash()
    admin = fee_payer.pubkey()
    notary_config, notary_bump = derive_notary_config_snapshot_pda(admin, 1, pid)
    del notary_bump

    # The SDK is the sole source of Anchor instruction encoding.
    sdk = _sdk_client(client, payer=fee_payer, program_id=pid)
    try:
        notary_signature = sdk.initialize_notary_config(2, [Pubkey.from_string(a), Pubkey.from_string(b)])[1]
        if notary_signature:
            _assert_signature_success(client, notary_signature, "localtest_notary_bootstrap_failed")
    except Exception as exc:
        raise LocaltestChainBootstrapError("localtest_notary_bootstrap_failed") from exc

    mint = Keypair()
    try:
        rent = client.get_minimum_balance_for_rent_exemption(82, commitment=Finalized).value
        _send_one(
            client,
            [
                create_account(CreateAccountParams(from_pubkey=fee_payer.pubkey(), to_pubkey=mint.pubkey(), lamports=rent, space=82, owner=TOKEN_PROGRAM_ID)),
                initialize_mint(InitializeMintParams(decimals=0, program_id=TOKEN_PROGRAM_ID, mint=mint.pubkey(), mint_authority=fee_payer.pubkey(), freeze_authority=None)),
            ],
            [fee_payer, mint],
            fee_payer,
        )
    except Exception as exc:
        raise LocaltestChainBootstrapError("localtest_quote_mint_bootstrap_failed") from exc

    initial_slot = rpc.finalized_slot()
    initial_time = rpc.block_time(initial_slot)
    if initial_time is None:
        raise LocaltestChainBootstrapError("localtest_bootstrap_block_time_unavailable")
    open_ts = initial_time
    lock_ts = initial_time
    resolve_ts = initial_time + 2
    market, _ = derive_market_pda(fee_payer.pubkey(), resolver, open_ts, market_nonce, pid)
    market_signature = ""
    try:
        market_signature = sdk.initialize_market_v2(
            resolver_hash=resolver,
            open_ts=open_ts,
            market_nonce=market_nonce,
            lock_ts=lock_ts,
            resolve_ts=resolve_ts,
            notary_config=notary_config,
            oracle_authority=fee_payer.pubkey(),
            quote_mint=mint.pubkey(),
        )
        _assert_signature_success(client, market_signature, "localtest_market_bootstrap_failed")
    except Exception as exc:
        raise LocaltestChainBootstrapError("localtest_market_bootstrap_failed") from exc

    if wait_for_resolve:
        finalized_slot, finalized_block_time = _wait_for_resolve_time(rpc, resolve_ts)
    else:
        finalized_slot = rpc.finalized_slot()
        finalized_block_time = rpc.block_time(finalized_slot)
        if finalized_block_time is None:
            raise LocaltestChainBootstrapError("localtest_bootstrap_block_time_unavailable")

    snapshot = None
    snapshot_deadline = time.monotonic() + 90
    while time.monotonic() < snapshot_deadline:
        candidate = rpc.finalized_accounts((str(market), str(notary_config)), min_context_slot=finalized_slot)
        if candidate.accounts[str(market)] is not None and candidate.accounts[str(notary_config)] is not None:
            snapshot = candidate
            break
        time.sleep(0.15)
    if snapshot is None:
        raise LocaltestChainBootstrapError("localtest_bootstrap_finalized_snapshot_timeout")
    if snapshot.context_slot < finalized_slot:
        raise LocaltestChainBootstrapError("localtest_bootstrap_snapshot_stale")
    market_account = snapshot.accounts[str(market)]
    notary_account = snapshot.accounts[str(notary_config)]
    if market_account is None or notary_account is None or market_account.owner != str(pid) or notary_account.owner != str(pid):
        try:
            observed = [str(item.pubkey) for item in client.get_program_accounts(pid, commitment=Finalized, encoding="base64").value]
        except Exception:
            observed = []
        try:
            status_value = client.get_signature_statuses([Signature.from_string(market_signature)], search_transaction_history=True).value[0]
            status_debug = repr(status_value)
            tx = client.get_transaction(Signature.from_string(market_signature), commitment=Finalized, max_supported_transaction_version=0)
            meta = getattr(tx.value, "transaction", None)
            debug = repr(getattr(meta, "meta", None))
        except Exception as exc:
            debug = repr(exc)
            status_debug = "status_error=" + repr(exc)
        raise LocaltestChainBootstrapError(f"localtest_bootstrap_accounts_missing:{market_account is not None}:{notary_account is not None}:{market}:{notary_config}:observed={observed}:market_signature={market_signature}:status={status_debug}:tx={debug[-4000:]}")
    m = _market_fields(market_account.data)
    n = _notary_fields(notary_account.data)
    expected_market, expected_bump = derive_market_pda(Pubkey.from_string(m["creator"]), resolver, open_ts, market_nonce, pid)
    expected_notary, expected_notary_bump = derive_notary_config_snapshot_pda(Pubkey.from_string(n["admin"]), 1, pid)
    if str(expected_market) != str(market) or expected_bump != m["bump"] or str(expected_notary) != str(notary_config) or expected_notary_bump != n["bump"]:
        raise LocaltestChainBootstrapError("localtest_bootstrap_pda_mismatch")
    if m["notary_config"] != str(notary_config) or m["creator"] != str(fee_payer.pubkey()) or m["market_nonce"] != market_nonce or m["resolver_hash"] != resolver or m["status"] != 0 or m["outcome"] != 0 or m["resolved_ts"] != 0 or m["proof_hash"] != bytes(32) or m["public_inputs_hash"] != bytes(32):
        raise LocaltestChainBootstrapError("localtest_market_state_invalid")
    if n["admin"] != str(admin) or n["threshold"] != 2 or n["count"] != 2 or n["version"] != 1 or n["keys"] != [a, b]:
        raise LocaltestChainBootstrapError("localtest_notary_state_invalid")

    values = {
        "schema": CHAIN_BINDING_SCHEMA,
        "version": 1,
        "cluster_classification": "FUNCTIONAL_TEST_ONLY",
        "genesis_hash": genesis,
        "program_id": str(pid),
        "signer_a_public_key": a,
        "signer_b_public_key": b,
        "notary_config": str(notary_config),
        "notary_config_version": 1,
        "threshold": 2,
        "market": str(market),
        "creator": str(fee_payer.pubkey()),
        "market_nonce": market_nonce,
        "resolver_definition_hash": resolver_definition_hash,
        "open_ts": open_ts,
        "lock_ts": lock_ts,
        "resolve_ts": resolve_ts,
        "outcome": outcome,
        "evidence_hash": evidence_hash,
        "proof_hash": proof_hash,
        "public_inputs_hash": public_inputs_hash,
        "finalized_bootstrap_slot": finalized_slot,
        "finalized_bootstrap_block_time": finalized_block_time,
        "finalized_account_context_slot": snapshot.context_slot,
    }
    return LocaltestChainBindingV1.from_mapping(values)
