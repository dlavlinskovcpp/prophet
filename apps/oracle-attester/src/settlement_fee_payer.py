"""Dedicated Solana fee-payer signing for settlement execution.

Resolution authorization remains the durable Vault A/B Ed25519 bundle.  This module
only signs the Solana transaction envelope with one dedicated fee-payer keypair.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction


class SettlementFeePayerError(RuntimeError):
    pass


class SettlementFeePayerConfigError(SettlementFeePayerError):
    pass


class SettlementFeePayerSigningError(SettlementFeePayerError):
    pass


class FilesystemFeePayerSigner:
    """Filesystem-backed Solana CLI-style fee-payer keypair.

    The accepted file format is intentionally singular: a JSON array containing
    exactly 64 integer bytes.  Base58 strings, 32-byte seeds, seed phrases, and
    inline runtime-config private material are not accepted here.
    """

    __slots__ = ("_keypair", "_filesystem_loaded", "_source_path")

    def __init__(
        self,
        keypair: Keypair,
        *,
        _filesystem_loaded: bool = False,
        _source_path: Path | None = None,
    ) -> None:
        if not isinstance(keypair, Keypair):
            raise SettlementFeePayerConfigError("fee_payer_keypair_invalid")
        self._keypair = keypair
        self._filesystem_loaded = bool(_filesystem_loaded)
        self._source_path = _source_path

    @classmethod
    def from_environment(
        cls,
        keypair_path_env: str,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> "FilesystemFeePayerSigner":
        source = os.environ if environ is None else environ
        raw_path = source.get(keypair_path_env)
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise SettlementFeePayerConfigError("fee_payer_keypair_path_unresolved")
        return cls.from_path(raw_path)

    @classmethod
    def from_path(cls, path: str | Path) -> "FilesystemFeePayerSigner":
        keypair_path = Path(path)
        if not keypair_path.is_file():
            raise SettlementFeePayerConfigError("fee_payer_keypair_file_missing")
        try:
            raw = keypair_path.read_text(encoding="utf-8")
            parsed = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SettlementFeePayerConfigError("fee_payer_keypair_file_invalid") from exc
        if (
            not isinstance(parsed, list)
            or len(parsed) != 64
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > 255
                for value in parsed
            )
        ):
            raise SettlementFeePayerConfigError("fee_payer_keypair_file_invalid")
        try:
            keypair = Keypair.from_bytes(bytes(parsed))
        except Exception as exc:
            raise SettlementFeePayerConfigError("fee_payer_keypair_file_invalid") from exc
        return cls(keypair, _filesystem_loaded=True, _source_path=keypair_path.resolve())

    @property
    def public_key(self) -> Pubkey:
        return self._keypair.pubkey()

    @property
    def is_test_signer(self) -> bool:
        if not self._filesystem_loaded or self._source_path is None:
            return True
        # Match the repository's production policy of rejecting fixture/test material.
        for part in self._source_path.parts:
            lowered = part.lower()
            if lowered in {"test", "tests", "fixture", "fixtures"}:
                return True
        filename = self._source_path.name.lower()
        if filename.startswith("test_") or "fixture" in filename:
          return True
        return False

    def sign_transaction_message(self, message: MessageV0) -> VersionedTransaction:
        if not isinstance(message, MessageV0):
            raise SettlementFeePayerSigningError("fee_payer_message_invalid")
        header = message.header
        account_keys = tuple(message.account_keys)
        if header.num_required_signatures != 1 or not account_keys:
            raise SettlementFeePayerSigningError("unexpected_transaction_signer_set")
        if account_keys[0] != self.public_key:
            raise SettlementFeePayerSigningError("fee_payer_not_required_signer")
        try:
            transaction = VersionedTransaction(message, [self._keypair])
            results = tuple(transaction.verify_with_results())
            if results != (True,):
                raise SettlementFeePayerSigningError("fee_payer_transaction_signature_invalid")
            transaction.verify_and_hash_message()
        except SettlementFeePayerSigningError:
            raise
        except Exception as exc:
            raise SettlementFeePayerSigningError("fee_payer_transaction_signing_failed") from exc
        return transaction
