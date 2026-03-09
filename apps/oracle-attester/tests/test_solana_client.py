from types import SimpleNamespace

from solders.pubkey import Pubkey

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
