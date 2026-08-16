import os
import socket

import pytest

from src.config import settings
from src.proof_fetcher import (
    LocalFileProofFetcher,
    ProofFetchConfigurationError,
    ProofFetchError,
    make_fetcher,
)


def _root(tmp_path):
    root = tmp_path / "proof-store"
    root.mkdir()
    return root


def _assert_code(exc_info, code):
    assert exc_info.value.code == code


def test_valid_proof_and_public_inputs_inside_root_succeed(tmp_path):
    root = _root(tmp_path)
    (root / "proof.bin").write_bytes(b"proofdata")
    (root / "pi.bin").write_bytes(b"pidata")

    result = LocalFileProofFetcher(root).fetch("file:proof.bin:pi.bin")

    assert result.proof_bytes == b"proofdata"
    assert result.public_inputs_bytes == b"pidata"
    assert "proof_path" not in result.meta
    assert "public_inputs_path" not in result.meta


def test_relative_traversal_rejected(tmp_path):
    root = _root(tmp_path)
    (root / "pi.bin").write_bytes(b"pi")
    (tmp_path / "secret").write_bytes(b"test-only-secret")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch("file:../secret:pi.bin")
    _assert_code(exc, "invalid_ref")


def test_nested_traversal_rejected(tmp_path):
    root = _root(tmp_path)
    (root / "pi.bin").write_bytes(b"pi")
    (tmp_path / "secret").write_bytes(b"test-only-secret")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch("file:nested/../../secret:pi.bin")
    _assert_code(exc, "invalid_ref")


@pytest.mark.parametrize(
    "proof_path",
    [
        "%2e%2e/secret",
        "%252e%252e/secret",
        "nested/%2e%2e/%2e%2e/secret",
    ],
)
def test_encoded_traversal_rejected(tmp_path, proof_path):
    root = _root(tmp_path)
    (root / "pi.bin").write_bytes(b"pi")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch(f"file:{proof_path}:pi.bin")
    _assert_code(exc, "invalid_ref")


def test_absolute_path_outside_root_rejected(tmp_path):
    root = _root(tmp_path)
    outside = tmp_path / "outside-proof.bin"
    outside.write_bytes(b"test-only-secret")
    (root / "pi.bin").write_bytes(b"pi")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch(f"file:{outside}:pi.bin")
    _assert_code(exc, "invalid_ref")
    assert str(outside) not in str(exc.value)


def test_mounted_looking_keypair_absolute_path_rejected(tmp_path):
    root = _root(tmp_path)
    (root / "pi.bin").write_bytes(b"pi")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch("file:/app/oracle-keypair.json:pi.bin")
    _assert_code(exc, "invalid_ref")
    assert "/app/oracle-keypair.json" not in str(exc.value)


def test_symlink_inside_root_pointing_outside_rejected(tmp_path):
    root = _root(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"test-only-secret")
    (root / "pi.bin").write_bytes(b"pi")
    link = root / "link.bin"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not supported on this platform")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch("file:link.bin:pi.bin")
    _assert_code(exc, "path_escape")


def test_directory_rejected(tmp_path):
    root = _root(tmp_path)
    (root / "proof-dir").mkdir()
    (root / "pi.bin").write_bytes(b"pi")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch("file:proof-dir:pi.bin")
    _assert_code(exc, "not_regular")


def test_fifo_rejected_without_opening(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO is not supported on this platform")
    root = _root(tmp_path)
    fifo = root / "proof.pipe"
    os.mkfifo(fifo)
    (root / "pi.bin").write_bytes(b"pi")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch("file:proof.pipe:pi.bin")
    _assert_code(exc, "not_regular")


def test_unix_socket_rejected_without_opening():
    import tempfile
    from pathlib import Path

    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("UNIX sockets are not supported on this platform")

    # macOS has a small sockaddr_un.sun_path limit. pytest's tmp_path can be
    # long enough to make bind() fail before the fetcher is exercised.
    with tempfile.TemporaryDirectory(prefix="p03-", dir="/tmp") as short_dir:
        root = Path(short_dir)
        socket_path = root / "p.sock"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(socket_path))
            (root / "pi.bin").write_bytes(b"pi")
            with pytest.raises(ProofFetchError) as exc:
                LocalFileProofFetcher(root).fetch("file:p.sock:pi.bin")
            _assert_code(exc, "not_regular")
        finally:
            sock.close()


def test_missing_file_rejected(tmp_path):
    root = _root(tmp_path)
    (root / "pi.bin").write_bytes(b"pi")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch("file:missing.bin:pi.bin")
    _assert_code(exc, "not_found")


def test_oversized_proof_rejected_before_open(tmp_path, monkeypatch):
    root = _root(tmp_path)
    (root / "proof.bin").write_bytes(b"x" * 17)
    (root / "pi.bin").write_bytes(b"pi")
    fetcher = LocalFileProofFetcher(root, proof_max_bytes=16)

    def unexpected_open(*_args, **_kwargs):
        pytest.fail("oversized proof must be rejected before opening/reading")

    monkeypatch.setattr(fetcher, "_open_relative_no_follow", unexpected_open)
    with pytest.raises(ProofFetchError) as exc:
        fetcher.fetch("file:proof.bin:pi.bin")
    _assert_code(exc, "too_large")


def test_oversized_public_inputs_rejected(tmp_path):
    root = _root(tmp_path)
    (root / "proof.bin").write_bytes(b"proof")
    (root / "pi.bin").write_bytes(b"x" * 17)
    fetcher = LocalFileProofFetcher(root, public_inputs_max_bytes=16)

    with pytest.raises(ProofFetchError) as exc:
        fetcher.fetch("file:proof.bin:pi.bin")
    _assert_code(exc, "too_large")


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "proof.bin:pi.bin",
        "file:",
        "file:proof.bin",
        "file::pi.bin",
        "file:proof.bin:",
        "file:nested//proof.bin:pi.bin",
        "file:./proof.bin:pi.bin",
        "file:proof.bin:nested//pi.bin",
        "file:proof.bin:pi.bin:extra",
    ],
)
def test_malformed_proof_ref_rejected(tmp_path, ref):
    root = _root(tmp_path)
    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root).fetch(ref)
    _assert_code(exc, "invalid_ref")


def test_valid_nested_files_inside_root_succeed(tmp_path):
    root = _root(tmp_path)
    nested = root / "market" / "proofs"
    nested.mkdir(parents=True)
    (nested / "proof.bin").write_bytes(b"nested-proof")
    (nested / "pi.json").write_bytes(b'{"value":1}')

    result = LocalFileProofFetcher(root).fetch(
        "file:market/proofs/proof.bin:market/proofs/pi.json"
    )
    assert result.proof_bytes == b"nested-proof"
    assert result.public_inputs_bytes == b'{"value":1}'


def test_two_roots_cannot_be_crossed(tmp_path):
    root_a = tmp_path / "root-a"
    root_b = tmp_path / "root-b"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "pi.bin").write_bytes(b"pi")
    (root_b / "proof.bin").write_bytes(b"other-root-proof")

    with pytest.raises(ProofFetchError) as exc:
        LocalFileProofFetcher(root_a).fetch("file:../root-b/proof.bin:pi.bin")
    _assert_code(exc, "invalid_ref")


def test_make_fetcher_local_fails_closed_without_root(monkeypatch):
    monkeypatch.setattr(settings, "PROOF_FETCH_MODE", "local")
    monkeypatch.setattr(settings, "PROOF_STORE_DIR", "")
    monkeypatch.setattr(settings, "PROOF_MAX_BYTES", 1024)
    monkeypatch.setattr(settings, "PUBLIC_INPUTS_MAX_BYTES", 1024)

    with pytest.raises(ProofFetchConfigurationError):
        make_fetcher()
