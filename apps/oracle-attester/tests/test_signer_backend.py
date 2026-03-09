import base64
import json
import subprocess

import pytest
from solders.keypair import Keypair

from src.signer_backend import CommandSignerBackend, LocalKeypairSignerBackend


def test_local_keypair_signer_backend_signs_loaded_key():
    kp = Keypair()
    backend = LocalKeypairSignerBackend({str(kp.pubkey()): kp})

    sig = backend.sign(kp.pubkey(), b"abc", {"market": "m1"})

    assert len(sig) == 64
    assert backend.loaded_pubkeys() == [str(kp.pubkey())]


def test_command_signer_backend_passes_json_payload(monkeypatch):
    kp = Keypair()
    seen = {}
    expected_sig = bytes([9] * 64)

    def mock_run(argv, input=None, capture_output=None, timeout=None, check=None):
        del capture_output, check
        seen["argv"] = argv
        seen["timeout"] = timeout
        seen["payload"] = json.loads(input.decode("utf-8"))
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps(
                {
                    "signature_b64": base64.b64encode(expected_sig).decode("ascii"),
                    "public_key": str(kp.pubkey()),
                }
            ).encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    backend = CommandSignerBackend("kms-wrapper --mode sign", 7.5)
    sig = backend.sign(kp.pubkey(), b"abc", {"market": "m1"})

    assert sig == expected_sig
    assert seen["argv"] == ["kms-wrapper", "--mode", "sign"]
    assert seen["timeout"] == 7.5
    assert seen["payload"]["public_key"] == str(kp.pubkey())
    assert seen["payload"]["context"]["market"] == "m1"


def test_command_signer_backend_rejects_bad_signature(monkeypatch):
    kp = Keypair()

    def mock_run(argv, input=None, capture_output=None, timeout=None, check=None):
        del input, capture_output, timeout, check
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps(
                {
                    "signature_b64": base64.b64encode(b"short").decode("ascii"),
                    "public_key": str(kp.pubkey()),
                }
            ).encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    backend = CommandSignerBackend("kms-wrapper sign", 5.0)
    with pytest.raises(RuntimeError):
        backend.sign(kp.pubkey(), b"x", {})
