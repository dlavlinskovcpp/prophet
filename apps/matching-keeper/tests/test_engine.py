from solders.pubkey import Pubkey

from prophet_sdk import OrderSide
from prophet_sdk.types import OrderAccount

from src.engine import MatchingEngine


def _pk(seed: int) -> Pubkey:
    return Pubkey.from_bytes(bytes([seed]) * 32)


def _order(*, market_seed: int, owner_seed: int, side: OrderSide, seq: int, price: int, qty: int) -> OrderAccount:
    return OrderAccount(
        market=_pk(market_seed),
        owner=_pk(owner_seed),
        side=side,
        seq=seq,
        limit_p_yes_e8=price,
        qty_remaining_atoms=qty,
        escrow_remaining_atoms=qty,
        fee_remaining_atoms=0,
        created_ts=1_700_000_000 + seq,
    )


def test_best_crossed_match_prefers_best_price_then_seq():
    market = _pk(1)
    engine = MatchingEngine()
    engine.replace_orders(
        market,
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=7, price=65_000_000, qty=30)),
            (_pk(11), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyYes, seq=5, price=70_000_000, qty=20)),
            (_pk(12), _order(market_seed=1, owner_seed=4, side=OrderSide.BuyNo, seq=6, price=60_000_000, qty=15)),
            (_pk(13), _order(market_seed=1, owner_seed=5, side=OrderSide.BuyNo, seq=3, price=60_000_000, qty=25)),
        ],
    )

    candidate = engine.best_crossed_match(market, max_qty_atoms=100)

    assert candidate is not None
    assert candidate.order_yes_pubkey == _pk(11)
    assert candidate.order_no_pubkey == _pk(13)
    assert candidate.qty_atoms == 20


def test_best_crossed_match_returns_none_for_uncrossed_book():
    market = _pk(1)
    engine = MatchingEngine()
    engine.replace_orders(
        market,
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=55_000_000, qty=10)),
            (_pk(12), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyNo, seq=2, price=60_000_000, qty=10)),
        ],
    )

    assert engine.best_crossed_match(market, max_qty_atoms=100) is None
