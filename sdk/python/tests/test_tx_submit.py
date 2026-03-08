from types import SimpleNamespace

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


class _FakeClient:
    def __init__(self):
        self.sent_opts = []

    def get_latest_blockhash(self, commitment=None):
        return SimpleNamespace(value=SimpleNamespace(blockhash="BLOCKHASH"))

    def send_raw_transaction(self, raw_tx: bytes, opts=None):
        self.sent_opts.append(opts)
        return SimpleNamespace(value="sig-123")

    def get_signature_statuses(self, sigs, search_transaction_history=True):
        status = SimpleNamespace(err=None, confirmation_status="confirmed")
        return SimpleNamespace(value=[status])


def _patch_tx_build(monkeypatch, captured: dict):
    def fake_try_compile(payer, instructions, address_lookup_table_accounts, recent_blockhash):
        captured["payer"] = payer
        captured["recent_blockhash"] = recent_blockhash
        return "fake-msg"

    class FakeVersionedTx:
        def __init__(self, msg, signers):
            captured["msg"] = msg
            captured["signers"] = list(signers)

        def __bytes__(self):
            return b"fake-tx"

    monkeypatch.setattr(tx_mod.MessageV0, "try_compile", staticmethod(fake_try_compile))
    monkeypatch.setattr(tx_mod, "VersionedTransaction", FakeVersionedTx)
    monkeypatch.setattr(tx_mod.time, "sleep", lambda _s: None)


def test_submit_and_confirm_dedupes_signers_by_pubkey(monkeypatch):
    captured = {}
    _patch_tx_build(monkeypatch, captured)

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

    assert sig == "sig-123"
    signer_keys = [bytes(s.pubkey()) for s in captured["signers"]]
    assert signer_keys == [b"A" * 32, b"B" * 32]
    assert client.sent_opts[0].skip_preflight is False


def test_submit_and_confirm_allows_skip_preflight_override(monkeypatch):
    captured = {}
    _patch_tx_build(monkeypatch, captured)

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
