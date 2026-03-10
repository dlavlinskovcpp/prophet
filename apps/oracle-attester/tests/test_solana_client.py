from types import SimpleNamespace

from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey

import src.solana_client as solana_client_mod
from src.solana_client import MarketLayout, SolanaClient


def _pk(seed: int) -> Pubkey:
    return Pubkey.from_bytes(bytes([seed]) * 32)


def test_extract_account_bytes_accepts_raw_bytes():
    client = object.__new__(SolanaClient)
    raw = b"market-bytes"

    assert client.extract_account_bytes(raw) == raw


def test_get_market_state_full_decodes_current_market_layout_from_raw_bytes():
    market = _pk(1)
    notary_config = _pk(5)
    resolver_hash = bytes([9]) * 32
    proof_hash = bytes([8]) * 32
    public_inputs_hash = bytes([7]) * 32

    payload = MarketLayout.build(
        {
            "authority": bytes(_pk(2)),
            "oracle_authority": bytes(_pk(3)),
            "quote_mint": bytes(_pk(4)),
            "quote_vault": bytes(_pk(6)),
            "fee_recipient": bytes(_pk(10)),
            "notary_config": bytes(notary_config),
            "resolver_hash": resolver_hash,
            "proof_hash": proof_hash,
            "public_inputs_hash": public_inputs_hash,
            "open_ts": 1_700_000_000,
            "lock_ts": 1_700_000_100,
            "resolve_ts": 1_700_000_200,
            "resolved_ts": 0,
            "min_order_qty_atoms": 1,
            "min_escrow_atoms": 1,
            "accrued_protocol_fees_atoms": 0,
            "next_order_seq": 3,
            "open_orders_total": 2,
            "max_open_orders_total": 128,
            "max_open_orders_per_user": 16,
            "protocol_fee_bps": 25,
            "reserved0": bytes(6),
            "quote_decimals": 9,
            "status": 0,
            "outcome": 0,
            "bump": 255,
        }
    )

    class _FakeRpcClient:
        def get_account_info(self, pubkey, commitment=None):
            assert pubkey == market
            return SimpleNamespace(value=SimpleNamespace(data=b"12345678" + payload))

    client = object.__new__(SolanaClient)
    client.client = _FakeRpcClient()

    state = client.get_market_state_full(market)

    assert state is not None
    assert state["notary_config"] == notary_config
    assert state["resolver_hash"] == resolver_hash
    assert state["proof_hash"] == proof_hash
    assert state["public_inputs_hash"] == public_inputs_hash
    assert state["open_ts"] == 1_700_000_000
    assert state["resolve_ts"] == 1_700_000_200
    assert state["status"] == 0


def test_submit_and_confirm_accepts_hash_object_blockhash(monkeypatch):
    captured = {}
    blockhash = Hash.default()
    payer = Keypair()

    class _FakeVersionedTx:
        def __init__(self, msg, signers):
            captured["msg"] = msg
            captured["signers"] = list(signers)

        def __bytes__(self):
            return b"fake-tx"

    class _FakeRpcClient:
        def get_latest_blockhash(self):
            return SimpleNamespace(value=SimpleNamespace(blockhash=blockhash))

        def send_raw_transaction(self, raw_tx, opts=None):
            captured["opts"] = opts
            return SimpleNamespace(value="sig-123")

        def confirm_transaction(self, sig, commitment=None):
            captured["confirmed"] = (sig, commitment)

    def _fake_try_compile(*, payer, instructions, address_lookup_table_accounts, recent_blockhash):
        captured["payer"] = payer
        captured["instructions"] = instructions
        captured["recent_blockhash"] = recent_blockhash
        return "fake-msg"

    monkeypatch.setattr(solana_client_mod.MessageV0, "try_compile", staticmethod(_fake_try_compile))
    monkeypatch.setattr(solana_client_mod, "VersionedTransaction", _FakeVersionedTx)

    client = object.__new__(SolanaClient)
    client.client = _FakeRpcClient()

    sig = client.submit_and_confirm([], payer)

    assert sig == "sig-123"
    assert captured["recent_blockhash"] == blockhash
