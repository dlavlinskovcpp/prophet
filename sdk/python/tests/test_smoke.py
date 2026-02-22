from prophet_sdk.client import ProphetClient
from prophet_sdk.pdas import derive_claim_pda, derive_market_pda

def test_sdk_has_new_helpers():
    assert hasattr(ProphetClient, "get_next_order_seq")
    assert hasattr(ProphetClient, "place_order_auto_seq")
    assert hasattr(ProphetClient, "fetch_orders_for_market")
    assert hasattr(ProphetClient, "fetch_orders_bulk")
    assert hasattr(ProphetClient, "resolve_market_signed")
    assert hasattr(ProphetClient, "resolve_market_threshold")
    assert hasattr(ProphetClient, "create_claim")
    assert hasattr(ProphetClient, "resolve_claim_signed")
    assert hasattr(ProphetClient, "resolve_claim_threshold")
    assert hasattr(ProphetClient, "redeem_claim")
    assert hasattr(ProphetClient, "redeem")
    assert hasattr(ProphetClient, "initialize_market_v2")
    assert hasattr(ProphetClient, "initialize_notary_config")

def test_pda_derivation():
    market, _ = derive_market_pda(bytes([0]*32), 100)
    assert str(market) is not None
    claim, _ = derive_claim_pda(derive_market_pda(bytes([1] * 32), 101)[0], 7)
    assert str(claim) is not None
