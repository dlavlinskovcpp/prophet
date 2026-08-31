from types import SimpleNamespace

import pytest

from prophet_sdk import tx as tx_mod


class _FakePubkey:
    def __init__(self, raw: bytes):
        self._raw = raw

    def __bytes__(self) -> bytes:
        return self._raw


class _FakeSigner:
    def __init__(self, raw_pubkey: bytes):
        self._pk = _FakePubkey(raw_pubkey)

    def pubkey(self) -> _FakePubkey:
        return self._pk


class _Clock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class _FakeClient:
    def __init__(self, statuses=None, send_errors=None, block_height=100):
        self.sent_bytes = []
        self.sent_opts = []
        self.status_calls = []
        self.blockhash_calls = 0
        self.statuses = list(statuses or [SimpleNamespace(err=None, confirmation_status="confirmed")])
        self.send_errors = list(send_errors or [])
        self.block_height = block_height

    def get_latest_blockhash(self, commitment=None):
        self.blockhash_calls += 1
        return SimpleNamespace(
            value=SimpleNamespace(blockhash="BLOCKHASH", last_valid_block_height=100)
        )

    def send_raw_transaction(self, raw_tx: bytes, opts=None):
        self.sent_bytes.append(raw_tx)
        self.sent_opts.append(opts)
        if self.send_errors:
            error = self.send_errors.pop(0)
            if error is not None:
                raise error
        return SimpleNamespace(value="sig-local")

    def get_signature_statuses(self, signatures, search_transaction_history=True):
        self.status_calls.append((signatures, search_transaction_history))
        status = self.statuses[0]
        if len(self.statuses) > 1:
            self.statuses.pop(0)
        return SimpleNamespace(value=[status])

    def get_block_height(self, commitment=None):
        return SimpleNamespace(value=self.block_height)


def _patch_tx_build(monkeypatch, captured: dict, clock: _Clock):
    def fake_try_compile(payer, instructions, address_lookup_table_accounts, recent_blockhash):
        captured["payer"] = payer
        captured["recent_blockhash"] = recent_blockhash
        captured["compile_count"] = captured.get("compile_count", 0) + 1
        return "fake-msg"

    class FakeVersionedTx:
        def __init__(self, msg, signers):
            captured["msg"] = msg
            captured["signers"] = list(signers)
            self.signatures = ["sig-local"]

        def __bytes__(self):
            captured["serialize_count"] = captured.get("serialize_count", 0) + 1
            return b"fixed-signed-transaction"

    monkeypatch.setattr(tx_mod.MessageV0, "try_compile", staticmethod(fake_try_compile))
    monkeypatch.setattr(tx_mod, "VersionedTransaction", FakeVersionedTx)
    monkeypatch.setattr(tx_mod.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(tx_mod.time, "sleep", clock.sleep)


def test_submit_and_confirm_prepares_once_and_dedupes_signers(monkeypatch):
    captured = {}
    clock = _Clock()
    _patch_tx_build(monkeypatch, captured, clock)
    client = _FakeClient()
    payer = _FakeSigner(b"A" * 32)
    same_as_payer = _FakeSigner(b"A" * 32)
    signer_b = _FakeSigner(b"B" * 32)
    signer_b_dup = _FakeSigner(b"B" * 32)

    sig = tx_mod.submit_and_confirm(
        client=client,
        instructions=[],
        payer=payer,
        signers=[same_as_payer, signer_b, signer_b_dup],
        timeout_s=1,
    )

    assert sig == "sig-local"
    assert captured["compile_count"] == 1
    assert captured["serialize_count"] == 1
    signer_keys = [bytes(s.pubkey()) for s in captured["signers"]]
    assert signer_keys == [b"A" * 32, b"B" * 32]
    assert client.blockhash_calls == 1
    assert client.sent_bytes == [b"fixed-signed-transaction"]
    assert client.sent_opts[0].skip_preflight is False
    assert client.sent_opts[0].preflight_commitment == tx_mod.Confirmed


def test_submit_and_confirm_allows_skip_preflight_override(monkeypatch):
    captured = {}
    clock = _Clock()
    _patch_tx_build(monkeypatch, captured, clock)
    client = _FakeClient()
    payer = _FakeSigner(b"P" * 32)

    tx_mod.submit_and_confirm(
        client=client,
        instructions=[],
        payer=payer,
        timeout_s=1,
        skip_preflight=True,
    )

    assert client.sent_opts[0].skip_preflight is True
    assert client.sent_opts[0].preflight_commitment == tx_mod.Confirmed


def test_send_timeout_after_acceptance_reconciles_exact_signature(monkeypatch):
    captured = {}
    clock = _Clock()
    _patch_tx_build(monkeypatch, captured, clock)
    client = _FakeClient(send_errors=[TimeoutError("accepted then timed out")])

    sig = tx_mod.submit_and_confirm(client, [], _FakeSigner(b"Q" * 32), timeout_s=1)

    assert sig == "sig-local"
    assert client.sent_bytes == [b"fixed-signed-transaction"]


def test_connection_reset_rebroadcasts_exact_bytes_without_rebuilding(monkeypatch):
    captured = {}
    clock = _Clock()
    _patch_tx_build(monkeypatch, captured, clock)
    client = _FakeClient(
        statuses=[None, None, SimpleNamespace(err=None, confirmation_status="confirmed")],
        send_errors=[ConnectionResetError("accepted then reset"), None],
    )

    sig = tx_mod.submit_and_confirm(client, [], _FakeSigner(b"R" * 32), timeout_s=2)

    assert sig == "sig-local"
    assert client.sent_bytes == [b"fixed-signed-transaction", b"fixed-signed-transaction"]
    assert captured["compile_count"] == 1


def test_requested_finalized_commitment_is_not_satisfied_by_confirmed(monkeypatch):
    captured = {}
    clock = _Clock()
    _patch_tx_build(monkeypatch, captured, clock)
    client = _FakeClient(
        statuses=[
            SimpleNamespace(err=None, confirmation_status="confirmed"),
            SimpleNamespace(err=None, confirmation_status="finalized"),
        ]
    )

    sig = tx_mod.submit_and_confirm(
        client,
        [],
        _FakeSigner(b"S" * 32),
        timeout_s=2,
        commitment="finalized",
    )

    assert sig == "sig-local"
    assert len(client.status_calls) == 2


def test_on_chain_error_is_not_reported_as_success(monkeypatch):
    captured = {}
    clock = _Clock()
    _patch_tx_build(monkeypatch, captured, clock)
    client = _FakeClient(statuses=[SimpleNamespace(err={"InstructionError": [0, "Custom"]}, confirmation_status="confirmed")])

    with pytest.raises(tx_mod.TransactionExecutionError, match="failed on-chain"):
        tx_mod.submit_and_confirm(client, [], _FakeSigner(b"T" * 32), timeout_s=1)


def test_expiry_without_terminal_status_raises_non_secret_unknown_commit_state(monkeypatch):
    captured = {}
    clock = _Clock()
    _patch_tx_build(monkeypatch, captured, clock)
    client = _FakeClient(statuses=[None], send_errors=[TimeoutError("rpc timeout")], block_height=101)

    with pytest.raises(tx_mod.UnknownCommitState) as raised:
        tx_mod.submit_and_confirm(client, [], _FakeSigner(b"U" * 32), timeout_s=1)

    error = raised.value
    assert error.signature == "sig-local"
    assert len(error.transaction_digest) == 64
    assert error.last_valid_block_height == 100
    assert not hasattr(error, "raw_bytes")
    assert "rpc timeout" not in str(error)


def test_pre_send_rejection_does_not_attempt_submission(monkeypatch):
    captured = {}
    clock = _Clock()
    _patch_tx_build(monkeypatch, captured, clock)
    monkeypatch.setattr(
        tx_mod.MessageV0,
        "try_compile",
        staticmethod(lambda **_: (_ for _ in ()).throw(ValueError("invalid instruction"))),
    )
    client = _FakeClient()

    with pytest.raises(tx_mod.TransactionPreparationError, match="before submission"):
        tx_mod.submit_and_confirm(client, [], _FakeSigner(b"V" * 32), timeout_s=1)

    assert client.sent_bytes == []
