import struct
from types import SimpleNamespace

from solders.pubkey import Pubkey

import prophet_sdk.client as client_mod
from prophet_sdk.client import ProphetClient
from prophet_sdk.pdas import derive_market_pda, derive_notary_config_pda

def test_sdk_has_new_helpers():
    assert hasattr(ProphetClient, "get_next_order_seq")
    assert hasattr(ProphetClient, "place_order_auto_seq")
    assert hasattr(ProphetClient, "fetch_orders_for_market")
    assert hasattr(ProphetClient, "fetch_orders_bulk")
    assert hasattr(ProphetClient, "resolve_market_threshold")
    assert hasattr(ProphetClient, "redeem")
    assert hasattr(ProphetClient, "transfer_market_authority")
    assert hasattr(ProphetClient, "lock_market")
    assert hasattr(ProphetClient, "unlock_market")
    assert hasattr(ProphetClient, "sync_market_status")
    assert hasattr(ProphetClient, "update_market_schedule")
    assert hasattr(ProphetClient, "set_market_fee_config")
    assert hasattr(ProphetClient, "withdraw_protocol_fees")
    assert hasattr(ProphetClient, "emergency_resolve_invalid")
    assert hasattr(ProphetClient, "initialize_market_v2")
    assert hasattr(ProphetClient, "initialize_notary_config")

def test_pda_derivation():
    market, bump = derive_market_pda(bytes([0]*32), 100)
    assert str(market) is not None


def _encode_notary_config(*, admin: Pubkey, threshold: int, notary_keys, version: int = 1) -> bytes:
    body = bytearray()
    body += bytes(admin)
    body += bytes([threshold])
    body += bytes([len(notary_keys)])
    body += bytes([255])
    body += bytes(5)
    body += struct.pack("<Q", version)
    for pk in notary_keys:
        body += bytes(pk)
    return b"12345678" + bytes(body)


def test_initialize_notary_config_treats_existing_pda_as_success(monkeypatch):
    payer = SimpleNamespace(pubkey=lambda: Pubkey.from_bytes(bytes([7]) * 32))
    program_id = client_mod.SYSTEM_PROGRAM_ID
    cfg_pda, _ = derive_notary_config_pda(payer.pubkey(), program_id)
    notary = Pubkey.from_bytes(bytes([9]) * 32)

    class _FakeRpcClient:
        def get_account_info(self, pubkey, commitment=None):
            assert pubkey == cfg_pda
            return SimpleNamespace(
                value=SimpleNamespace(
                    data=_encode_notary_config(
                        admin=payer.pubkey(),
                        threshold=1,
                        notary_keys=[notary],
                    )
                )
            )

    client = ProphetClient.__new__(ProphetClient)
    client.client = _FakeRpcClient()
    client.payer = payer
    client.program_id = program_id
    client._get_discriminator = lambda _name: b"discdisc"

    def _raise_submit(_rpc, _ixs, _payer):
        raise RuntimeError("account already in use")

    monkeypatch.setattr(client_mod, "submit_and_confirm", _raise_submit)

    actual_cfg, sig = client.initialize_notary_config(1, [notary])

    assert actual_cfg == cfg_pda
    assert sig == ""


def test_initialize_notary_config_reraises_when_existing_pda_shape_differs(monkeypatch):
    payer = SimpleNamespace(pubkey=lambda: Pubkey.from_bytes(bytes([7]) * 32))
    program_id = client_mod.SYSTEM_PROGRAM_ID
    cfg_pda, _ = derive_notary_config_pda(payer.pubkey(), program_id)
    requested_notary = Pubkey.from_bytes(bytes([9]) * 32)
    existing_notary = Pubkey.from_bytes(bytes([10]) * 32)

    class _FakeRpcClient:
        def get_account_info(self, pubkey, commitment=None):
            assert pubkey == cfg_pda
            return SimpleNamespace(
                value=SimpleNamespace(
                    data=_encode_notary_config(
                        admin=payer.pubkey(),
                        threshold=2,
                        notary_keys=[existing_notary],
                    )
                )
            )

    client = ProphetClient.__new__(ProphetClient)
    client.client = _FakeRpcClient()
    client.payer = payer
    client.program_id = program_id
    client._get_discriminator = lambda _name: b"discdisc"

    def _raise_submit(_rpc, _ixs, _payer):
        raise RuntimeError("account already in use")

    monkeypatch.setattr(client_mod, "submit_and_confirm", _raise_submit)

    try:
        client.initialize_notary_config(1, [requested_notary])
    except RuntimeError as err:
        assert "already in use" in str(err)
    else:
        raise AssertionError("expected initialize_notary_config to re-raise on mismatched config")
