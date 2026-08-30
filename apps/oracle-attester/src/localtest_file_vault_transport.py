"""Localtest-only file-backed implementation of the private Vault transport.

This module is deliberately incapable of acting as a production signer.  It
implements only the two methods consumed by ``IndependentSignerVaultAdapter``
and accepts only the frozen settlement-message shape.
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import Any, Mapping

from solders.keypair import Keypair


_SETTLEMENT_DOMAIN = b"PROPHET_RESOLVE_V2"
_SEED_BYTES = 32
_KEY_VERSION = 1


class LocaltestFileVaultTransportError(RuntimeError):
    """The localtest seed or its fixed transport binding is unsafe."""


def _require_localtest(environment: object, mode: object) -> None:
    if environment != "localtest" or mode != "test":
        raise LocaltestFileVaultTransportError("localtest_transport_environment_rejected")


def _safe_parent(path: Path) -> None:
    try:
        details = path.parent.lstat()
    except OSError as exc:
        raise LocaltestFileVaultTransportError("localtest_seed_parent_unavailable") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise LocaltestFileVaultTransportError("localtest_seed_parent_invalid")
    if details.st_mode & 0o077:
        raise LocaltestFileVaultTransportError("localtest_seed_parent_permissions_invalid")


def _validate_existing_seed(path: Path) -> bytes:
    try:
        details = path.lstat()
    except OSError as exc:
        raise LocaltestFileVaultTransportError("localtest_seed_unavailable") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise LocaltestFileVaultTransportError("localtest_seed_file_invalid")
    if details.st_mode & 0o077:
        raise LocaltestFileVaultTransportError("localtest_seed_permissions_invalid")
    if hasattr(os, "geteuid") and details.st_uid != os.geteuid():
        raise LocaltestFileVaultTransportError("localtest_seed_owner_invalid")
    if details.st_size != _SEED_BYTES:
        raise LocaltestFileVaultTransportError("localtest_seed_size_invalid")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            value = os.read(descriptor, _SEED_BYTES + 1)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise LocaltestFileVaultTransportError("localtest_seed_open_invalid") from exc
    if len(value) != _SEED_BYTES:
        raise LocaltestFileVaultTransportError("localtest_seed_size_invalid")
    return value


def _create_seed_exclusively(path: Path) -> bytes:
    seed = secrets.token_bytes(_SEED_BYTES)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise LocaltestFileVaultTransportError("localtest_seed_already_exists") from exc
    except OSError as exc:
        raise LocaltestFileVaultTransportError("localtest_seed_create_failed") from exc
    try:
        os.fchmod(descriptor, 0o600)
        written = os.write(descriptor, seed)
        if written != _SEED_BYTES:
            raise LocaltestFileVaultTransportError("localtest_seed_write_failed")
        os.fsync(descriptor)
    except Exception:
        # The path is intentionally left in place: silently repairing a
        # partially-created signer identity would be less safe than failing.
        raise
    finally:
        os.close(descriptor)
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError:
        # Some supported filesystems do not permit directory fsync.  The file
        # itself was synced; startup still validates it strictly on restart.
        pass
    return seed


class LocaltestFileVaultTransport:
    """One fixed role/key localtest signing transport; never a key registry."""

    def __init__(
        self,
        *,
        environment: str,
        mode: str,
        signer_role: str,
        signer_id: str,
        vault_key_name: str,
        key_version: int,
        seed_path: str | Path,
        initialize: bool = False,
    ) -> None:
        _require_localtest(environment, mode)
        if signer_role not in {"A", "B"} or not isinstance(signer_id, str) or not signer_id:
            raise LocaltestFileVaultTransportError("localtest_transport_identity_invalid")
        if not isinstance(vault_key_name, str) or not vault_key_name or key_version != _KEY_VERSION:
            raise LocaltestFileVaultTransportError("localtest_transport_key_binding_invalid")
        if not isinstance(initialize, bool):
            raise LocaltestFileVaultTransportError("localtest_seed_initialization_invalid")
        path = Path(seed_path)
        if not path.is_absolute() or path.name != "signer.seed":
            raise LocaltestFileVaultTransportError("localtest_seed_path_invalid")
        _safe_parent(path)
        seed = _create_seed_exclusively(path) if initialize else _validate_existing_seed(path)
        try:
            self._key = Keypair.from_seed(seed)
        except Exception as exc:
            raise LocaltestFileVaultTransportError("localtest_seed_invalid") from exc
        self._environment = environment
        self._mode = mode
        self._signer_role = signer_role
        self._signer_id = signer_id
        self._vault_key_name = vault_key_name
        self._key_version = _KEY_VERSION
        self._seed_path = path

    @property
    def public_key(self) -> str:
        return str(self._key.pubkey())

    @property
    def signer_id(self) -> str:
        return self._signer_id

    @property
    def vault_key_name(self) -> str:
        return self._vault_key_name

    @property
    def key_version(self) -> int:
        return self._key_version

    @property
    def seed_path(self) -> Path:
        return self._seed_path

    def read_key_metadata(self, key_name: str) -> Mapping[str, Any]:
        if key_name != self._vault_key_name:
            raise LocaltestFileVaultTransportError("localtest_transport_key_name_rejected")
        return {
            "type": "ed25519",
            "supports_signing": True,
            "keys": {"1": {"public_key": self.public_key}},
        }

    def sign_versioned(self, key_name: str, message: bytes, *, key_version: int) -> tuple[int, bytes]:
        if key_name != self._vault_key_name or key_version != _KEY_VERSION:
            raise LocaltestFileVaultTransportError("localtest_transport_key_binding_rejected")
        if type(message) is not bytes or len(message) != 235 or not message.startswith(_SETTLEMENT_DOMAIN):
            raise LocaltestFileVaultTransportError("localtest_transport_message_rejected")
        return _KEY_VERSION, bytes(self._key.sign_message(message))
