"""Restart/crash-boundary tests use fresh SQLite repository objects each time."""
import pytest
from dataclasses import replace

from src.signing_journal import (
    A_SIGNING,
    BOTH_SIGNED,
    NOT_STARTED,
    SIGNATURE_RECORDED,
    SIGNATURE_STATUS_UNKNOWN,
    SigningJournal,
    SigningJournalBindingError,
    SigningJournalConflict,
    SigningJournalUncertain,
)
from src.vault_transit_threshold_signer import ThresholdResolutionSigner
from src.vault_transit_signer_identity import VaultSignerRotationError, VaultTransitSignerClient

from tests.test_signing_journal import _bindings, _fixture, _message


def test_restart_before_intent_has_no_recovery_record_and_can_start(tmp_path, monkeypatch):
    _, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    assert reopened.scan_recovery() == ()
    ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened).resume_2_of_2(_message())
    assert [call[0] for call in transport.calls] == ["key-a", "key-b"]
    reopened.close()

def test_restart_after_intent_before_signer_marker_resumes_normally(tmp_path, monkeypatch):
    _, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened)
    status = reopened.inspect_recovery(intent.signing_scope_id)
    assert (status.signer_a_state, status.signer_b_state, status.category) == (NOT_STARTED, NOT_STARTED, "INCOMPLETE")
    recovered.resume_2_of_2(message)
    assert [item[0] for item in transport.calls] == ["key-a", "key-b"]
    reopened.close()


def test_marker_before_vault_is_explicitly_uncertain_after_real_restart(tmp_path, monkeypatch):
    _, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    assert journal.begin_signer(intent.signing_scope_id, "A") is None
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened)
    assert reopened.get(intent.signing_scope_id).state == A_SIGNING
    assert reopened.inspect_recovery(intent.signing_scope_id).signer_a_state == SIGNATURE_STATUS_UNKNOWN
    with pytest.raises(SigningJournalUncertain): recovered.resume_2_of_2(message)
    with pytest.raises(SigningJournalUncertain): recovered.resume_2_of_2(message)
    assert transport.calls == []
    reopened.close()


def test_crash_after_vault_receives_a_request_remains_fail_closed(tmp_path, monkeypatch):
    _, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.begin_signer(intent.signing_scope_id, "A")
    # The backend received a real request, but a simulated process crash loses
    # the returned public signature before journal persistence.
    a.sign_canonical_message(message)
    assert [call[0] for call in transport.calls] == ["key-a"]
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened)
    with pytest.raises(SigningJournalUncertain): recovered.resume_2_of_2(message)
    assert [call[0] for call in transport.calls] == ["key-a"]
    with pytest.raises(SigningJournalConflict): reopened.reserve_intent(_message(outcome="YES"), signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    reopened.close()


def test_a_durable_b_not_started_reuses_a_and_starts_b_after_restart(tmp_path, monkeypatch):
    _, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.begin_signer(intent.signing_scope_id, "A")
    journal.record_signature(intent.signing_scope_id, "A", a.sign_canonical_message(message))
    assert [call[0] for call in transport.calls] == ["key-a"]
    journal.close(); reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened)
    assert reopened.inspect_recovery(intent.signing_scope_id).signer_a_state == SIGNATURE_RECORDED
    recovered.resume_2_of_2(message)
    assert [call[0] for call in transport.calls] == ["key-a", "key-b"]
    assert reopened.get(intent.signing_scope_id).state == BOTH_SIGNED
    reopened.close()


def test_b_uncertain_after_a_durable_does_not_repeat_a_or_b(tmp_path, monkeypatch):
    _, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.begin_signer(intent.signing_scope_id, "A"); journal.record_signature(intent.signing_scope_id, "A", a.sign_canonical_message(message))
    journal.begin_signer(intent.signing_scope_id, "B"); b.sign_canonical_message(message)
    assert [call[0] for call in transport.calls] == ["key-a", "key-b"]
    journal.close(); reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened)
    status = reopened.inspect_recovery(intent.signing_scope_id)
    assert (status.signer_a_state, status.signer_b_state, status.category) == (SIGNATURE_RECORDED, SIGNATURE_STATUS_UNKNOWN, "UNCERTAIN")
    with pytest.raises(SigningJournalUncertain): recovered.resume_2_of_2(message)
    assert [call[0] for call in transport.calls] == ["key-a", "key-b"]
    reopened.close()


def test_completed_bundle_recovery_is_read_only_and_makes_zero_vault_calls(tmp_path, monkeypatch):
    threshold, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); original = threshold.sign_2_of_2(message)
    scope = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1]).signing_scope_id
    journal.close(); reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened)
    before = list(transport.calls); assert recovered.resume_2_of_2(message) == original
    assert transport.calls == before
    assert reopened.inspect_recovery(scope).category == "COMPLETE"
    reopened.close()


def test_startup_scan_is_read_only_and_never_calls_vault(tmp_path, monkeypatch):
    _, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    assert journal.scan_recovery()[0].signing_scope_id == intent.signing_scope_id
    assert transport.calls == []
    journal.close()


def test_recovery_rejects_wrong_message_signer_or_key_version_before_vault(tmp_path, monkeypatch):
    _, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.close(); reopened = SigningJournal(tmp_path / "journal.sqlite")
    recovered = ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=reopened)
    with pytest.raises(SigningJournalConflict): recovered.resume_2_of_2(_message(outcome="YES"))
    with pytest.raises(VaultSignerRotationError): ThresholdResolutionSigner(signer_a=b, signer_b=a, journal=reopened).resume_2_of_2(message)
    wrong_version_a = VaultTransitSignerClient(signing=a.signing, signer=replace(a.signer, expected_key_version=2, key_epochs=()), config_fingerprint="test", vault_token="token", transport=a._transport)
    with pytest.raises(VaultSignerRotationError): ThresholdResolutionSigner(signer_a=wrong_version_a, signer_b=b, journal=reopened).resume_2_of_2(message)
    assert transport.calls == []
    reopened.close()


def test_durable_transitions_never_expose_completion_without_signature(tmp_path, monkeypatch):
    _, journal, a, b, _ = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    assert journal.get(intent.signing_scope_id).signer_a_result is None
    journal.begin_signer(intent.signing_scope_id, "A"); assert journal.get(intent.signing_scope_id).state == A_SIGNING and journal.get(intent.signing_scope_id).signer_a_result is None
    journal.record_signature(intent.signing_scope_id, "A", a.sign_canonical_message(message)); assert journal.get(intent.signing_scope_id).state == "A_SIGNED" and journal.get(intent.signing_scope_id).signer_a_result is not None
    journal.begin_signer(intent.signing_scope_id, "B"); assert journal.get(intent.signing_scope_id).signer_b_result is None
    journal.record_signature(intent.signing_scope_id, "B", b.sign_canonical_message(message)); final = journal.get(intent.signing_scope_id)
    assert final.state == BOTH_SIGNED and final.signer_a_result is not None and final.signer_b_result is not None
    journal.close()
