from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from src.admission_grant_replay_journal import (
    ALREADY_CONSUMED, CONSUMED,
    AdmissionGrantReplayJournal,
    AdmissionGrantReplayJournalBindingError,
    AdmissionGrantReplayJournalError,
)


NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def _consume(journal, *, grant_id="a" * 32, request_hash="b" * 64, run_id="c" * 32):
    return journal.consume_once(grant_id=grant_id, admission_request_sha256=request_hash, acceptance_run_id=run_id, consumed_at=NOW, valid_until=NOW + timedelta(hours=1))


def test_first_consume_duplicate_conflict_and_immutable_original_record(tmp_path):
    journal = AdmissionGrantReplayJournal(tmp_path / "a.sqlite", signer_role="A")
    assert _consume(journal).status == CONSUMED
    assert _consume(journal).status == ALREADY_CONSUMED
    assert _consume(journal, request_hash="d" * 64).status == ALREADY_CONSUMED
    assert _consume(journal, run_id="e" * 32).status == ALREADY_CONSUMED
    record = journal.get("a" * 32)
    assert (record.admission_request_sha256, record.acceptance_run_id) == ("b" * 64, "c" * 32)
    journal.close()


def test_restart_and_crash_after_consumption_remain_consumed(tmp_path):
    path = tmp_path / "a.sqlite"
    first = AdmissionGrantReplayJournal(path, signer_role="A")
    assert _consume(first).status == CONSUMED
    first.close()  # Models a crash after durable consume and before response.
    second = AdmissionGrantReplayJournal(path, signer_role="A")
    assert _consume(second).status == ALREADY_CONSUMED
    second.close()


def test_expired_row_never_becomes_reusable(tmp_path):
    journal = AdmissionGrantReplayJournal(tmp_path / "a.sqlite", signer_role="A")
    journal.consume_once(grant_id="a" * 32, admission_request_sha256="b" * 64, acceptance_run_id="c" * 32, consumed_at=NOW, valid_until=NOW - timedelta(seconds=1))
    assert _consume(journal).status == ALREADY_CONSUMED
    journal.close()


def test_independent_connections_have_exactly_one_winner(tmp_path):
    path = tmp_path / "a.sqlite"
    first, second = AdmissionGrantReplayJournal(path, signer_role="A"), AdmissionGrantReplayJournal(path, signer_role="A")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda journal: _consume(journal).status, (first, second)))
    assert sorted(results) == [ALREADY_CONSUMED, CONSUMED]
    first.close(); second.close()


@pytest.mark.parametrize("initial, reopened", (("A", "B"), ("B", "A")))
def test_role_metadata_prevents_cross_role_reopen(tmp_path, initial, reopened):
    path = tmp_path / "role.sqlite"
    journal = AdmissionGrantReplayJournal(path, signer_role=initial)
    journal.close()
    with pytest.raises(AdmissionGrantReplayJournalBindingError, match="metadata_mismatch"):
        AdmissionGrantReplayJournal(path, signer_role=reopened)


def test_schema_and_metadata_corruption_fail_closed(tmp_path):
    path = tmp_path / "a.sqlite"
    journal = AdmissionGrantReplayJournal(path, signer_role="A")
    journal.close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE admission_grant_replay_metadata SET value = 'B' WHERE key = 'signer_role'")
    raw.commit(); raw.close()
    with pytest.raises(AdmissionGrantReplayJournalBindingError, match="metadata_mismatch"):
        AdmissionGrantReplayJournal(path, signer_role="A")


def test_unknown_schema_and_storage_failure_fail_closed(tmp_path):
    path = tmp_path / "a.sqlite"
    journal = AdmissionGrantReplayJournal(path, signer_role="A")
    journal.close()
    raw = sqlite3.connect(path); raw.execute("PRAGMA user_version = 99"); raw.commit(); raw.close()
    with pytest.raises(AdmissionGrantReplayJournalBindingError, match="unsupported"):
        AdmissionGrantReplayJournal(path, signer_role="A")
    good = AdmissionGrantReplayJournal(tmp_path / "b.sqlite", signer_role="A")
    good._db.close()
    with pytest.raises(AdmissionGrantReplayJournalError):
        _consume(good)


def test_rejects_non_absolute_role_and_untyped_trusted_times(tmp_path):
    with pytest.raises(AdmissionGrantReplayJournalBindingError):
        AdmissionGrantReplayJournal("relative.sqlite", signer_role="A")
    journal = AdmissionGrantReplayJournal(tmp_path / "a.sqlite", signer_role="A")
    with pytest.raises(AdmissionGrantReplayJournalBindingError):
        journal.consume_once(grant_id="a" * 32, admission_request_sha256="b" * 64, acceptance_run_id="c" * 32, consumed_at="now", valid_until=NOW)
    journal.close()
