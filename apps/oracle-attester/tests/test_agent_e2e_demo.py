import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "demo_agent_market.py"
spec = importlib.util.spec_from_file_location("demo_agent_market", SCRIPT)
demo = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(demo)


def test_deterministic_agent_demo_resolves_with_two_verifiers():
    first, second = demo.run(False), demo.run(False)
    assert first == second
    assert first["state"] == "resolved"
    assert first["threshold_signer_result"] == {"threshold": 2, "signature_count": 2}
    assert first["settlement_tx"] == first["legacy_settlement_message_hash"]
    assert first["redemption"]["amount"] == 100


def test_adversarial_agent_demo_persists_conflict_and_never_signs():
    result = demo.run(True)
    assert result["state"] == "conflicted"
    assert result["agreement"] == "outcome_conflict"
    assert result["conflict_persisted"] is True
    assert result["threshold_signer_result"] is None
    assert result["settlement_tx"] is None
