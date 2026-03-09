from prophet_sdk.client import ProphetClient
from prophet_sdk.pdas import derive_market_pda

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
