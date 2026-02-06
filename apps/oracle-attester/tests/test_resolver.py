from src.resolver import compute_resolver_hash, evaluate_resolver, ResolverDefinition
from src.types import OutcomeEnum

def test_resolver_hash_stable():
    def1 = {
        "url": "https://api.test",
        "path": "a.b",
        "predicate": "equals",
        "target_value": 100,
        "method": "GET"
    }
    h1 = compute_resolver_hash(def1)
    h2 = compute_resolver_hash(def1)
    assert h1 == h2
    
    def2 = def1.copy()
    def2["target_value"] = 101
    h3 = compute_resolver_hash(def2)
    assert h1 != h3

def test_resolver_eval_yes_no_invalid():
    res = ResolverDefinition(
        url="http://test",
        path="status",
        predicate="equals",
        target_value=200
    )
    
    assert evaluate_resolver(res, {"status": 200}) == OutcomeEnum.YES
    assert evaluate_resolver(res, {"status": 404}) == OutcomeEnum.NO
    assert evaluate_resolver(res, {"other": 200}) == OutcomeEnum.INVALID
    assert evaluate_resolver(res, {"status": [200]}) == OutcomeEnum.INVALID

def test_resolver_strict_dict():
    # Correct predicate
    res = ResolverDefinition(url="x", path="x", predicate="equals", target_value=1)
    
    # Empty dict -> INVALID
    assert evaluate_resolver(res, {}) == OutcomeEnum.INVALID
    
    # List input -> INVALID (handled by try/except block in evaluator)
    # The type hint says Dict but runtime might pass List if caller is lax.
    # evaluate_resolver handles this gracefully.
    assert evaluate_resolver(res, ["not", "dict"]) == OutcomeEnum.INVALID