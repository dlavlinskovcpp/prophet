import struct
from types import SimpleNamespace

from solders.pubkey import Pubkey

import prophet_sdk.client as client_mod
from prophet_sdk.client import ProphetClient
from prophet_sdk.pdas import (
    derive_market_pda,
    derive_order_pda,
    derive_notary_config_pda,
    derive_notary_config_snapshot_pda,
    derive_position_pda,
)

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
    assert not hasattr(ProphetClient, "emergency_resolve_invalid")
    assert hasattr(ProphetClient, "initialize_market_v2")
    assert hasattr(ProphetClient, "initialize_notary_config")
    assert hasattr(ProphetClient, "rotate_notary_config")

def test_pda_derivation():
    market, bump = derive_market_pda(Pubkey.default(), bytes([0]*32), 100, 0)
    assert str(market) is not None


def test_market_namespace_binds_creator_and_nonce_without_changing_order_or_position_rules():
    resolver = bytes([3]) * 32
    creator_a = Pubkey.from_bytes(bytes([4]) * 32)
    creator_b = Pubkey.from_bytes(bytes([5]) * 32)
    market_a0, _ = derive_market_pda(creator_a, resolver, -7, 0)
    market_a1, _ = derive_market_pda(creator_a, resolver, -7, 1)
    market_b0, _ = derive_market_pda(creator_b, resolver, -7, 0)

    assert market_a0 != market_a1
    assert market_a0 != market_b0
    order, _ = derive_order_pda(market_a0, creator_a, 0)
    position, _ = derive_position_pda(market_a0, creator_a)
    assert order != position


def test_notary_snapshot_pda_preserves_legacy_v1_and_versions_successors():
    admin = Pubkey.from_bytes(bytes([4]) * 32)
    program_id = client_mod.SYSTEM_PROGRAM_ID
    legacy, legacy_bump = derive_notary_config_pda(admin, program_id)
    v1, v1_bump = derive_notary_config_snapshot_pda(admin, 1, program_id)
    v2, _ = derive_notary_config_snapshot_pda(admin, 2, program_id)
    v3, _ = derive_notary_config_snapshot_pda(admin, 3, program_id)

    assert (v1, v1_bump) == (legacy, legacy_bump)
    assert v1 != v2 != v3
    try:
        derive_notary_config_snapshot_pda(admin, 0, program_id)
    except ValueError:
        pass
    else:
        raise AssertionError("zero snapshot version must be rejected")


def test_legacy_update_helper_fails_closed_before_rpc():
    client = ProphetClient.__new__(ProphetClient)
    try:
        client.update_notary_config(1, [Pubkey.from_bytes(bytes([8]) * 32)])
    except ValueError as err:
        assert "immutable" in str(err).lower()
    else:
        raise AssertionError("legacy update helper must reject immutable snapshot mutation")


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


def test_rotate_notary_config_builds_successor_snapshot(monkeypatch):
    payer = SimpleNamespace(pubkey=lambda: Pubkey.from_bytes(bytes([12]) * 32))
    program_id = client_mod.SYSTEM_PROGRAM_ID
    previous, _ = derive_notary_config_pda(payer.pubkey(), program_id)
    old_notary = Pubkey.from_bytes(bytes([13]) * 32)
    new_notary = Pubkey.from_bytes(bytes([14]) * 32)

    class _FakeRpcClient:
        def get_account_info(self, pubkey, commitment=None):
            assert pubkey == previous
            return SimpleNamespace(
                value=SimpleNamespace(
                    data=_encode_notary_config(
                        admin=payer.pubkey(),
                        threshold=1,
                        notary_keys=[old_notary],
                        version=1,
                    )
                )
            )

    client = ProphetClient.__new__(ProphetClient)
    client.client = _FakeRpcClient()
    client.payer = payer
    client.program_id = program_id
    client._get_discriminator = lambda name: b"discdisc"

    captured = {}

    def _capture_submit(_rpc, ixs, _payer):
        captured["ix"] = ixs[0]
        return "sig"

    monkeypatch.setattr(client_mod, "submit_and_confirm", _capture_submit)

    successor, sig = client.rotate_notary_config(previous, 2, 1, [new_notary])
    expected, _ = derive_notary_config_snapshot_pda(payer.pubkey(), 2, program_id)

    assert successor == expected
    assert sig == "sig"
    assert captured["ix"].program_id == program_id
