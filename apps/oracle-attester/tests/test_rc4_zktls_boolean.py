import pytest

from src.zktls_providers.reclaim_http import parse_verify_response


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"valid": True}, True),
        ({"valid": False}, False),
        ({"valid": "false"}, False),
        ({"valid": "true"}, False),
        ({"valid": 1}, False),
        ({"valid": None}, False),
        ({}, False),
        ({"ok": True, "valid": False}, False),
        ({"ok": False, "valid": True}, False),
        ({"ok": True, "valid": True}, True),
        ({"ok": False, "valid": False}, False),
    ],
)
def test_legacy_reclaim_status_is_strict_json_boolean(payload, expected):
    valid, _, _ = parse_verify_response(payload)
    assert valid is expected


@pytest.mark.parametrize(
    "payload",
    [
        {"valid": "false"},
        {"valid": "true"},
        {"valid": 1},
        {"valid": None},
        {"ok": True, "valid": False},
        {"ok": False, "valid": True},
    ],
)
def test_invalid_or_conflicting_status_fails_closed_with_reason(payload):
    valid, reason, _ = parse_verify_response(payload)
    assert valid is False
    assert reason
