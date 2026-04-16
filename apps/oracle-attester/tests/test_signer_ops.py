from solders.keypair import Keypair

from src.signer_backend import LocalKeypairSignerBackend
from src.signer_ops import (
    bootstrap_aws_kms_keys,
    discover_pubkeys_from_signer_health,
    derive_remote_signer_health_url,
    run_backend_dry_run,
    write_allowlist_file,
)


def _ed25519_spki_from_pubkey(raw_pubkey: bytes) -> bytes:
    if len(raw_pubkey) != 32:
        raise ValueError("expected 32-byte Ed25519 pubkey")
    return bytes.fromhex("302a300506032b6570032100") + raw_pubkey


def test_bootstrap_aws_kms_keys_returns_allowlist_pubkeys():
    signer = Keypair()

    class MockKmsClient:
        def get_public_key(self, KeyId):
            return {
                "KeyId": f"arn:aws:kms:us-east-1:123456789012:key/{KeyId}",
                "KeySpec": "ECC_NIST_EDWARDS25519",
                "KeyUsage": "SIGN_VERIFY",
                "SigningAlgorithms": ["ED25519_SHA_512"],
                "PublicKey": _ed25519_spki_from_pubkey(bytes(signer.pubkey())),
            }

    payload = bootstrap_aws_kms_keys(
        region_name="us-east-1",
        key_ids=["alias/prophet-notary"],
        endpoint_url="",
        timeout_s=3.0,
        client=MockKmsClient(),
    )

    assert payload["allowlist_pubkeys"] == [str(signer.pubkey())]
    assert payload["keys"][0]["resolved_key_id"].endswith("alias/prophet-notary")


def test_write_allowlist_file_normalizes_and_sorts(tmp_path):
    first = str(Keypair().pubkey())
    second = str(Keypair().pubkey())
    path = tmp_path / "signer_allowlist.txt"

    entries = write_allowlist_file(path, [second, first, second])

    assert entries == sorted([first, second])
    assert path.read_text(encoding="utf-8").splitlines() == entries


def test_derive_remote_signer_health_url_rewrites_sign_path():
    assert (
        derive_remote_signer_health_url("https://signer.example")
        == "https://signer.example/health"
    )
    assert (
        derive_remote_signer_health_url("https://signer.example/api/v1/sign")
        == "https://signer.example/api/v1/health"
    )


def test_run_backend_dry_run_uses_loaded_pubkeys_when_none_requested():
    signer = Keypair()
    backend = LocalKeypairSignerBackend({str(signer.pubkey()): signer})

    payload = run_backend_dry_run(
        backend,
        public_keys=[],
        message=b"prophet-dry-run",
        context={"operation": "dry_run"},
    )

    assert payload["loaded_pubkeys"] == [str(signer.pubkey())]
    assert payload["results"][0]["public_key"] == str(signer.pubkey())
    assert payload["results"][0]["signature_len"] == 64


def test_discover_pubkeys_from_signer_health_reads_loaded_pubkeys():
    signer = Keypair()

    payload = discover_pubkeys_from_signer_health(
        {"loaded_pubkeys": [str(signer.pubkey())]}
    )

    assert payload == [str(signer.pubkey())]
