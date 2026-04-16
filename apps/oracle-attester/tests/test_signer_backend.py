import base64
import json
import subprocess

import pytest
from solders.keypair import Keypair

from src.signer_backend import AwsKmsSignerBackend, CommandSignerBackend, LocalKeypairSignerBackend


def _ed25519_spki_from_pubkey(raw_pubkey: bytes) -> bytes:
    if len(raw_pubkey) != 32:
        raise ValueError("expected 32-byte Ed25519 pubkey")
    return bytes.fromhex("302a300506032b6570032100") + raw_pubkey


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


def test_command_signer_backend_health_reports_loaded_pubkeys():
    kp = Keypair()

    backend = CommandSignerBackend(
        "kms-wrapper sign",
        5.0,
        public_keys=[str(kp.pubkey())],
    )
    health = backend.health()

    assert health["backend_ready"] is True
    assert health["loaded_pubkeys"] == [str(kp.pubkey())]
    assert health["pubkeys"] == [str(kp.pubkey())]


def test_aws_kms_signer_backend_loads_pubkeys_and_signs(monkeypatch):
    kp = Keypair()
    expected_sig = bytes([4] * 64)
    seen = {"sign": []}

    class MockKmsClient:
        def get_public_key(self, KeyId):
            seen["get_public_key"] = KeyId
            return {
                "KeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
                "KeySpec": "ECC_NIST_EDWARDS25519",
                "KeyUsage": "SIGN_VERIFY",
                "SigningAlgorithms": ["ED25519_SHA_512"],
                "PublicKey": _ed25519_spki_from_pubkey(bytes(kp.pubkey())),
            }

        def sign(self, **kwargs):
            seen["sign"].append(kwargs)
            return {"Signature": expected_sig}

    monkeypatch.setattr(
        "src.signer_backend._make_aws_kms_client",
        lambda **kwargs: MockKmsClient(),
    )

    backend = AwsKmsSignerBackend(
        region_name="us-east-1",
        key_ids=["alias/prophet-notary"],
        endpoint_url="",
        timeout_s=3.0,
    )
    sig = backend.sign(kp.pubkey(), b"abc", {"market": "m1"})

    assert sig == expected_sig
    assert backend.loaded_pubkeys() == [str(kp.pubkey())]
    assert seen["get_public_key"] == "alias/prophet-notary"
    assert seen["sign"][0]["KeyId"] == "arn:aws:kms:us-east-1:123456789012:key/abc"
    assert seen["sign"][0]["Message"] == b"abc"
    assert seen["sign"][0]["MessageType"] == "RAW"
    assert seen["sign"][0]["SigningAlgorithm"] == "ED25519_SHA_512"


def test_aws_kms_signer_backend_rejects_wrong_key_spec(monkeypatch):
    kp = Keypair()

    class MockKmsClient:
        def get_public_key(self, KeyId):
            del KeyId
            return {
                "KeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
                "KeySpec": "RSA_2048",
                "KeyUsage": "SIGN_VERIFY",
                "SigningAlgorithms": ["RSASSA_PSS_SHA_256"],
                "PublicKey": _ed25519_spki_from_pubkey(bytes(kp.pubkey())),
            }

    monkeypatch.setattr(
        "src.signer_backend._make_aws_kms_client",
        lambda **kwargs: MockKmsClient(),
    )

    with pytest.raises(ValueError):
        AwsKmsSignerBackend(
            region_name="us-east-1",
            key_ids=["alias/prophet-notary"],
            endpoint_url="",
            timeout_s=3.0,
        )
