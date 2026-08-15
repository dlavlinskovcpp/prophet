import base64

import pytest
from solders.keypair import Keypair

from src.vault_transit import (
    VaultTransitClient,
    VaultTransitConfig,
    bootstrap_vault_transit_keys,
    build_vault_key_map_payload,
    parse_vault_public_key,
    parse_vault_signature,
    parse_vault_signature_with_version,
    read_vault_key_map,
    resolve_vault_key_name,
    write_vault_key_map_file,
)


def _ed25519_spki_from_pubkey(raw_pubkey: bytes) -> bytes:
    if len(raw_pubkey) != 32:
        raise ValueError("expected 32-byte Ed25519 pubkey")
    return bytes.fromhex("302a300506032b6570032100") + raw_pubkey


def test_parse_vault_signature_accepts_vault_prefix():
    expected = bytes([7] * 64)

    actual = parse_vault_signature(
        "vault:v1:" + base64.b64encode(expected).decode("ascii")
    )

    assert actual == expected
    assert parse_vault_signature_with_version("vault:v7:" + base64.b64encode(expected).decode("ascii")) == (7, expected)


def test_vault_transit_versioned_sign_sends_raw_message_and_requires_version():
    signer = Keypair()
    message = b"PROPHET_RESOLVE_V2" + bytes(32)
    signature = bytes(signer.sign_message(message))

    class Response:
        status_code = 200
        content = b"{}"
        text = "{}"
        reason_phrase = "OK"
        def json(self): return {"data": {"signature": "vault:v1:" + base64.b64encode(signature).decode("ascii")}}

    class Http:
        def __init__(self): self.body = None
        def request(self, method, url, headers=None, json=None):
            self.body = (method, url, json)
            return Response()

    http = Http()
    client = VaultTransitClient(VaultTransitConfig("http://127.0.0.1:8200", "", "token", "transit", 1.0, "", False, "", ""), client=http)
    assert client.sign_versioned("key-a", message, key_version=1) == (1, signature)
    assert http.body[2] == {"input": base64.b64encode(message).decode("ascii"), "key_version": 1}


def test_parse_vault_public_key_accepts_der_spki_base64():
    signer = Keypair()
    encoded = base64.b64encode(
        _ed25519_spki_from_pubkey(bytes(signer.pubkey()))
    ).decode("ascii")

    assert parse_vault_public_key(encoded) == str(signer.pubkey())


def test_bootstrap_vault_transit_keys_returns_allowlist_and_key_map():
    first = Keypair()
    second = Keypair()

    class MockVaultClient:
        def ensure_ed25519_key(self, key_name, **kwargs):
            del kwargs
            return (
                {
                    "type": "ed25519",
                    "latest_version": 1,
                    "supports_signing": True,
                },
                False,
            )

        def export_public_key(self, key_name):
            if key_name == "notary-1":
                return str(first.pubkey())
            if key_name == "notary-2":
                return str(second.pubkey())
            raise AssertionError(f"unexpected key {key_name}")

    payload = bootstrap_vault_transit_keys(
        config=VaultTransitConfig(
            addr="https://vault.example",
            namespace="",
            token="token",
            mount="transit",
            timeout_s=5.0,
            cacert="",
            skip_verify=False,
            key_name="",
            key_map_path="",
        ),
        key_names=["notary-1", "notary-2"],
        client=MockVaultClient(),
    )

    assert payload["allowlist_pubkeys"] == [str(first.pubkey()), str(second.pubkey())]
    assert payload["command_public_keys_csv"] == (
        f"{first.pubkey()},{second.pubkey()}"
    )
    assert payload["key_map"]["keys"][str(first.pubkey())]["key_name"] == "notary-1"
    assert payload["key_map"]["keys"][str(second.pubkey())]["key_name"] == "notary-2"


def test_vault_transit_client_reads_public_key_from_metadata_without_export():
    signer = Keypair()

    class MockResponse:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload
            self.content = b"{}"
            self.text = "{}"
            self.reason_phrase = "OK"

        def json(self):
            return self._payload

    class MockHttpClient:
        def __init__(self):
            self.calls = []

        def request(self, method, url, headers=None, json=None):
            del headers, json
            self.calls.append((method, url))
            if url.endswith("/v1/transit/keys/notary-1"):
                return MockResponse(
                    {
                        "data": {
                            "type": "ed25519",
                            "latest_version": 1,
                            "keys": {
                                "1": {
                                    "public_key": str(signer.pubkey()),
                                }
                            },
                        }
                    }
                )
            raise AssertionError(f"unexpected request: {method} {url}")

    transport = VaultTransitClient(
        VaultTransitConfig(
            addr="http://127.0.0.1:8200",
            namespace="",
            token="root",
            mount="transit",
            timeout_s=5.0,
            cacert="",
            skip_verify=False,
            key_name="",
            key_map_path="",
        ),
        client=MockHttpClient(),
    )

    assert transport.export_public_key("notary-1") == str(signer.pubkey())
    assert transport._client.calls == [("GET", "http://127.0.0.1:8200/v1/transit/keys/notary-1")]


def test_resolve_vault_key_name_reads_key_map(tmp_path):
    signer = Keypair()
    path = tmp_path / "vault-transit-key-map.json"
    payload = build_vault_key_map_payload(
        [{"solana_pubkey": str(signer.pubkey()), "key_name": "notary-1"}],
        mount="transit",
    )
    write_vault_key_map_file(path, payload)

    class UnusedClient:
        def export_public_key(self, key_name):
            raise AssertionError(key_name)

    assert read_vault_key_map(path)[str(signer.pubkey())]["key_name"] == "notary-1"
    assert (
        resolve_vault_key_name(
            str(signer.pubkey()),
            client=UnusedClient(),
            key_map_path=str(path),
        )
        == "notary-1"
    )


def test_resolve_vault_key_name_rejects_single_key_mismatch():
    expected = Keypair()
    actual = Keypair()

    class MockVaultClient:
        def export_public_key(self, key_name):
            assert key_name == "notary-1"
            return str(actual.pubkey())

    with pytest.raises(PermissionError):
        resolve_vault_key_name(
            str(expected.pubkey()),
            client=MockVaultClient(),
            key_name="notary-1",
        )
