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


def _match(orders, *, max_qty_atoms=100):
    market = _pk(1)
    engine = MatchingEngine()
    engine.replace_orders(market, orders)
    return engine.best_crossed_match(market, max_qty_atoms=max_qty_atoms)


def test_normal_best_pair_with_distinct_owners_remains_unchanged():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=7, price=65_000_000, qty=30)),
            (_pk(11), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyYes, seq=5, price=70_000_000, qty=20)),
            (_pk(12), _order(market_seed=1, owner_seed=4, side=OrderSide.BuyNo, seq=6, price=60_000_000, qty=15)),
            (_pk(13), _order(market_seed=1, owner_seed=5, side=OrderSide.BuyNo, seq=3, price=60_000_000, qty=25)),
        ]
    )

    assert candidate is not None
    assert candidate.order_yes_pubkey == _pk(11)
    assert candidate.order_no_pubkey == _pk(13)
    assert candidate.qty_atoms == 20


def test_same_owner_top_pair_uses_second_no_when_valid():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=70_000_000, qty=20)),
            (_pk(20), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=1, price=50_000_000, qty=20)),
            (_pk(21), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyNo, seq=2, price=60_000_000, qty=20)),
        ]
    )

    assert candidate is not None
    assert candidate.order_yes_pubkey == _pk(10)
    assert candidate.order_no_pubkey == _pk(21)


def test_same_owner_top_pair_uses_second_yes_when_valid():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=70_000_000, qty=20)),
            (_pk(11), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyYes, seq=2, price=65_000_000, qty=20)),
            (_pk(20), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=1, price=60_000_000, qty=20)),
            (_pk(21), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=2, price=61_000_000, qty=20)),
        ]
    )

    assert candidate is not None
    assert candidate.order_yes_pubkey == _pk(11)
    assert candidate.order_no_pubkey == _pk(20)


def test_several_self_owned_combinations_can_precede_valid_pair():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=70_000_000, qty=20)),
            (_pk(11), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=2, price=69_000_000, qty=20)),
            (_pk(12), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=3, price=68_000_000, qty=20)),
            (_pk(20), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=1, price=50_000_000, qty=20)),
            (_pk(21), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=2, price=55_000_000, qty=20)),
            (_pk(22), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=3, price=60_000_000, qty=20)),
            (_pk(23), _order(market_seed=1, owner_seed=4, side=OrderSide.BuyNo, seq=4, price=65_000_000, qty=20)),
        ]
    )

    assert candidate is not None
    assert candidate.order_yes_pubkey == _pk(10)
    assert candidate.order_no_pubkey == _pk(23)


def test_only_crossed_opportunities_are_self_match_returns_none():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=70_000_000, qty=20)),
            (_pk(20), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=1, price=50_000_000, qty=20)),
            (_pk(21), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyNo, seq=2, price=75_000_000, qty=20)),
            (_pk(11), _order(market_seed=1, owner_seed=4, side=OrderSide.BuyYes, seq=2, price=45_000_000, qty=20)),
        ]
    )

    assert candidate is None


def test_next_distinct_owner_pair_exists_but_is_not_crossed_returns_none():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=60_000_000, qty=20)),
            (_pk(11), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyYes, seq=2, price=50_000_000, qty=20)),
            (_pk(20), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=1, price=55_000_000, qty=20)),
            (_pk(21), _order(market_seed=1, owner_seed=4, side=OrderSide.BuyNo, seq=2, price=65_000_000, qty=20)),
        ]
    )

    assert candidate is None


def test_deterministic_sequence_tie_breaking_is_preserved():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyYes, seq=2, price=70_000_000, qty=20)),
            (_pk(11), _order(market_seed=1, owner_seed=4, side=OrderSide.BuyYes, seq=1, price=70_000_000, qty=20)),
            (_pk(20), _order(market_seed=1, owner_seed=5, side=OrderSide.BuyNo, seq=1, price=60_000_000, qty=20)),
        ]
    )

    assert candidate is not None
    assert candidate.order_yes_pubkey == _pk(11)


def test_deterministic_pubkey_tie_breaking_is_preserved():
    candidate = _match(
        [
            (_pk(11), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyYes, seq=1, price=70_000_000, qty=20)),
            (_pk(10), _order(market_seed=1, owner_seed=4, side=OrderSide.BuyYes, seq=1, price=70_000_000, qty=20)),
            (_pk(20), _order(market_seed=1, owner_seed=5, side=OrderSide.BuyNo, seq=1, price=60_000_000, qty=20)),
        ]
    )

    assert candidate is not None
    assert candidate.order_yes_pubkey == _pk(10)


def test_returned_quantity_is_min_of_both_remaining_and_max_qty():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=70_000_000, qty=30)),
            (_pk(20), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyNo, seq=1, price=60_000_000, qty=12)),
        ],
        max_qty_atoms=9,
    )

    assert candidate is not None
    assert candidate.qty_atoms == 9


def test_engine_never_returns_candidate_with_equal_owners():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=75_000_000, qty=20)),
            (_pk(11), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyYes, seq=2, price=70_000_000, qty=20)),
            (_pk(20), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyNo, seq=1, price=50_000_000, qty=20)),
            (_pk(21), _order(market_seed=1, owner_seed=4, side=OrderSide.BuyNo, seq=2, price=60_000_000, qty=20)),
        ]
    )

    assert candidate is not None
    assert candidate.order_yes.owner != candidate.order_no.owner


def test_best_crossed_match_returns_none_for_uncrossed_book():
    candidate = _match(
        [
            (_pk(10), _order(market_seed=1, owner_seed=2, side=OrderSide.BuyYes, seq=1, price=55_000_000, qty=10)),
            (_pk(12), _order(market_seed=1, owner_seed=3, side=OrderSide.BuyNo, seq=2, price=60_000_000, qty=10)),
        ]
    )

    assert candidate is None
