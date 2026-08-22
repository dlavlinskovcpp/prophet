"""Static audit for the immutable creator-and-nonce market namespace.

Anchor account constraints are compile-time macros, so this guard keeps a new
instruction from silently reintroducing the retired global market seed tuple.
"""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTRUCTIONS = ROOT / "programs" / "prophet" / "src" / "instructions"


def test_all_active_market_seed_users_bind_creator_and_nonce():
    users = [path for path in INSTRUCTIONS.glob("*.rs") if 'b"market"' in path.read_text()]
    assert users, "market seed audit must inspect active instruction sources"
    for path in users:
        source = path.read_text()
        assert "creator" in source, f"{path.relative_to(ROOT)} omits immutable creator market seed"
        assert "market_nonce" in source, f"{path.relative_to(ROOT)} omits immutable nonce market seed"
        assert 'seeds = [b"market", market.resolver_hash' not in source, (
            f"{path.relative_to(ROOT)} retains the retired global market seed tuple"
        )
