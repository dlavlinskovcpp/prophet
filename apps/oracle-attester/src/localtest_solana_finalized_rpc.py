"""Strict finalized-RPC adapter for the localtest fixed-role lane.

This module is intentionally not part of production composition.  It exposes
only the small ``FinalizedRpc`` protocol consumed by P0C1 and rejects every
endpoint/context that is not explicitly classified as a functional localtest.
"""
from __future__ import annotations

import base64
import binascii
from urllib.parse import urlsplit

from solana.rpc.api import Client
from solana.rpc.commitment import Finalized
from solders.pubkey import Pubkey
from solders.hash import Hash

from .signer_authorization import Account, FinalizedAccountRead, FinalizedAccountsRead


class LocaltestSolanaFinalizedRpcError(RuntimeError):
    """A malformed, stale, unavailable, or unsafe localtest RPC result."""


def _require_loopback(url: str) -> str:
    if not isinstance(url, str) or not url or url.strip() != url:
        raise LocaltestSolanaFinalizedRpcError("localtest_rpc_url_invalid")
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise LocaltestSolanaFinalizedRpcError("localtest_rpc_url_invalid")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise LocaltestSolanaFinalizedRpcError("localtest_rpc_loopback_required")
    if parsed.path not in {"", "/"}:
        raise LocaltestSolanaFinalizedRpcError("localtest_rpc_url_invalid")
    return url.rstrip("/")


def _slot(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LocaltestSolanaFinalizedRpcError(code)
    return value


def _response_value(response: object, code: str) -> object:
    try:
        return response.value  # solana-py typed RPC response
    except Exception as exc:
        raise LocaltestSolanaFinalizedRpcError(code) from exc


def _response_context(response: object, code: str) -> tuple[int, object]:
    value = _response_value(response, code)
    try:
        context = response.context
        slot = _slot(context.slot, "localtest_rpc_context_slot_invalid")
    except Exception as exc:
        raise LocaltestSolanaFinalizedRpcError(code) from exc
    return slot, value


def _decode_account(value: object, code: str) -> Account | None:
    if value is None:
        return None
    try:
        owner = str(value.owner)
        if str(Pubkey.from_string(owner)) != owner:
            raise ValueError
        data = value.data
        # solana-py exposes the already-decoded bytes on typed responses even
        # when the JSON-RPC request explicitly selected base64.
        if isinstance(data, bytes):
            raw = data
        elif isinstance(data, (list, tuple)) and len(data) == 2 and data[1] == "base64" and isinstance(data[0], str):
            raw = base64.b64decode(data[0].encode("ascii"), validate=True)
        else:
            raise ValueError
        if not isinstance(raw, bytes):
            raise ValueError
        lamports = value.lamports
        if isinstance(lamports, bool) or not isinstance(lamports, int) or lamports < 0:
            raise ValueError
        executable = value.executable
        if not isinstance(executable, bool):
            raise ValueError
        return Account(owner=owner, data=raw)
    except (ValueError, TypeError, AttributeError, UnicodeError, binascii.Error) as exc:
        raise LocaltestSolanaFinalizedRpcError(code) from exc


class LocaltestSolanaFinalizedRpc:
    """One-shot, finalized-only RPC view for the functional localtest lane."""

    def __init__(self, rpc_url: str, *, environment: str, mode: str, topology_classification: str, timeout_seconds: float = 10.0) -> None:
        if environment != "localtest" or mode != "test" or topology_classification != "FUNCTIONAL_TEST_ONLY":
            raise LocaltestSolanaFinalizedRpcError("localtest_rpc_context_rejected")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
            raise LocaltestSolanaFinalizedRpcError("localtest_rpc_timeout_invalid")
        self.rpc_url = _require_loopback(rpc_url)
        self._client = Client(self.rpc_url, timeout=float(timeout_seconds))

    def genesis_hash(self) -> str:
        try:
            value = _response_value(self._client.get_genesis_hash(), "localtest_rpc_genesis_failed")
            if not isinstance(value, (str, Hash)):
                raise ValueError
            # Existing P0C1 signed-package schemas carry the 32-byte cluster
            # identity as lowercase hex.  Normalize the validator's canonical
            # base58 getGenesisHash representation without inventing a value.
            return bytes(value if isinstance(value, Hash) else Hash.from_string(value)).hex()
        except LocaltestSolanaFinalizedRpcError:
            raise
        except Exception as exc:
            raise LocaltestSolanaFinalizedRpcError("localtest_rpc_genesis_failed") from exc

    def finalized_slot(self) -> int:
        try:
            return _slot(_response_value(self._client.get_slot(commitment=Finalized), "localtest_rpc_slot_failed"), "localtest_rpc_slot_invalid")
        except LocaltestSolanaFinalizedRpcError:
            raise
        except Exception as exc:
            raise LocaltestSolanaFinalizedRpcError("localtest_rpc_slot_failed") from exc

    def block_time(self, slot: int) -> int | None:
        _slot(slot, "localtest_rpc_block_time_slot_invalid")
        try:
            value = _response_value(self._client.get_block_time(slot), "localtest_rpc_block_time_failed")
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise ValueError
            return value
        except LocaltestSolanaFinalizedRpcError:
            raise
        except Exception as exc:
            raise LocaltestSolanaFinalizedRpcError("localtest_rpc_block_time_failed") from exc

    def finalized_account(self, pubkey: str, *, min_context_slot: int) -> FinalizedAccountRead:
        _slot(min_context_slot, "localtest_rpc_min_context_slot_invalid")
        try:
            key = Pubkey.from_string(pubkey)
            response = self._client.get_account_info(key, commitment=Finalized, encoding="base64")
            context_slot, value = _response_context(response, "localtest_rpc_account_response_invalid")
            if context_slot < min_context_slot:
                raise LocaltestSolanaFinalizedRpcError("localtest_rpc_stale_context")
            return FinalizedAccountRead(_decode_account(value, "localtest_rpc_account_malformed"), context_slot)
        except LocaltestSolanaFinalizedRpcError:
            raise
        except Exception as exc:
            raise LocaltestSolanaFinalizedRpcError("localtest_rpc_account_failed") from exc

    def finalized_accounts(self, pubkeys: tuple[str, str], *, min_context_slot: int) -> FinalizedAccountsRead:
        _slot(min_context_slot, "localtest_rpc_min_context_slot_invalid")
        if not isinstance(pubkeys, tuple) or len(pubkeys) != 2 or pubkeys[0] == pubkeys[1]:
            raise LocaltestSolanaFinalizedRpcError("localtest_rpc_account_set_invalid")
        try:
            keys = tuple(Pubkey.from_string(value) for value in pubkeys)
            response = self._client.get_multiple_accounts(list(keys), commitment=Finalized, encoding="base64")
            context_slot, values = _response_context(response, "localtest_rpc_multiple_accounts_response_invalid")
            if context_slot < min_context_slot or not isinstance(values, (list, tuple)) or len(values) != 2:
                raise LocaltestSolanaFinalizedRpcError("localtest_rpc_stale_or_malformed_snapshot")
            accounts = {name: _decode_account(value, "localtest_rpc_account_malformed") for name, value in zip(pubkeys, values)}
            return FinalizedAccountsRead(accounts, context_slot)
        except LocaltestSolanaFinalizedRpcError:
            raise
        except Exception as exc:
            raise LocaltestSolanaFinalizedRpcError("localtest_rpc_multiple_accounts_failed") from exc

    @property
    def client(self) -> Client:
        """Expose the already-bound client only to the localtest submitter."""
        return self._client
