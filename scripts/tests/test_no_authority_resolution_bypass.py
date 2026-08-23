"""Static protocol-surface regression checks for threshold-only settlement."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROGRAM = ROOT / "programs" / "prophet" / "src"


def _assignment_sources(fragment: str) -> set[Path]:
    return {
        source.relative_to(PROGRAM)
        for source in PROGRAM.rglob("*.rs")
        if fragment in source.read_text(encoding="utf-8")
    }


def test_threshold_resolution_is_the_only_market_settlement_write_path():
    threshold_source = Path("instructions/resolve_market_threshold.rs")
    threshold_code = (PROGRAM / threshold_source).read_text(encoding="utf-8")
    assert not (PROGRAM / "instructions" / "emergency_resolve_invalid.rs").exists()
    assert "emergency_resolve_invalid" not in (PROGRAM / "lib.rs").read_text(encoding="utf-8")

    expected_message = threshold_code.index("let expected_message = resolution_message_v2(")
    threshold_check = threshold_code.index("valid_count >= config.threshold")
    first_settlement_write = threshold_code.index("market.status = MarketStatus::Resolved")
    assert expected_message < threshold_check < first_settlement_write

    for fragment in (
        "market.status = MarketStatus::Resolved",
        "market.outcome = outcome",
        "market.proof_hash = proof_hash",
        "market.public_inputs_hash = public_inputs_hash",
        "market.resolved_ts = now",
    ):
        assert _assignment_sources(fragment) == {threshold_source}
