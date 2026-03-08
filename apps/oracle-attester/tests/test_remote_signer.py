import base64

import httpx
import pytest
from solders.keypair import Keypair

from src.attester import RemoteNotarySigner


def test_remote_notary_signer_success(monkeypatch):
    kp = Keypair()
    expected_sig = bytes([7] * 64)
    seen = {}

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, json=None, headers=None):
            seen["url"] = url
            seen["json"] = json
            seen["headers"] = headers
            req = httpx.Request("POST", url)
            return httpx.Response(
                200,
                json={
                    "signature_b64": base64.b64encode(expected_sig).decode("ascii"),
                    "public_key": str(kp.pubkey()),
                },
                request=req,
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    signer = RemoteNotarySigner("https://signer.example/sign", "k", 3.0)
    msg = b"abc"
    sig = signer.sign(kp.pubkey(), msg, {"market": "m1"})

    assert sig == expected_sig
    assert seen["url"] == "https://signer.example/sign"
    assert seen["json"]["public_key"] == str(kp.pubkey())
    assert seen["json"]["message_b64"] == base64.b64encode(msg).decode("ascii")
    assert seen["json"]["context"]["market"] == "m1"
    assert seen["headers"]["Authorization"] == "Bearer k"


def test_remote_notary_signer_fails_on_http_error(monkeypatch):
    kp = Keypair()

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, json=None, headers=None):
            req = httpx.Request("POST", url)
            return httpx.Response(500, text="boom", request=req)

    monkeypatch.setattr(httpx, "Client", MockClient)

    signer = RemoteNotarySigner("https://signer.example/sign", "", 3.0)
    with pytest.raises(RuntimeError):
        signer.sign(kp.pubkey(), b"x", {})


def test_remote_notary_signer_fails_on_bad_signature_shape(monkeypatch):
    kp = Keypair()

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, json=None, headers=None):
            req = httpx.Request("POST", url)
            return httpx.Response(
                200,
                json={
                    "signature_b64": base64.b64encode(b"short").decode("ascii"),
                    "public_key": str(kp.pubkey()),
                },
                request=req,
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    signer = RemoteNotarySigner("https://signer.example/sign", "", 3.0)
    with pytest.raises(RuntimeError):
        signer.sign(kp.pubkey(), b"x", {})
