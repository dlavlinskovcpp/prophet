"""Narrow Solana RPC surface used by Phase 6D2 settlement simulation only."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from solana.rpc.api import Client
from solders.hash import Hash
from solders.transaction import VersionedTransaction


class SettlementRpcError(RuntimeError):
    pass


class SettlementRpcConfigError(SettlementRpcError):
    pass


class SettlementRpcTransportError(SettlementRpcError):
    pass


class SettlementRpcResponseError(SettlementRpcError):
    pass


@dataclass(frozen=True)
class RpcSimulationResult:
    program_error: str | None
    logs: tuple[str, ...]
    units_consumed: int | None
    replacement_blockhash: str | None
    replacement_last_valid_block_height: int | None


class SolanaSettlementRpcClient:
    """Only getGenesisHash/getLatestBlockhash/simulateTransaction are exposed.

    The wrapped solana-py client is deliberately private.  Submission methods are
    not surfaced by this application boundary.
    """

    is_test_transport = False

    def __init__(
        self,
        rpc_url: str,
        *,
        timeout_seconds: int,
        commitment: str,
        require_https: bool = False,
    ) -> None:
        try:
            parsed = urlsplit(rpc_url)
            host = parsed.hostname
            port = parsed.port
        except (TypeError, ValueError) as exc:
            raise SettlementRpcConfigError("settlement_rpc_url_invalid") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or port == 0
        ):
            raise SettlementRpcConfigError("settlement_rpc_url_invalid")
        if require_https and parsed.scheme != "https":
            raise SettlementRpcConfigError("settlement_rpc_https_required")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise SettlementRpcConfigError("settlement_rpc_timeout_invalid")
        if commitment not in {"processed", "confirmed", "finalized"}:
            raise SettlementRpcConfigError("settlement_rpc_commitment_invalid")
        self._client = Client(rpc_url, commitment=commitment, timeout=timeout_seconds)
        self._commitment = commitment
        # Safe for logs/metrics: credentials, path, and query are intentionally omitted.
        self._endpoint_label = host if port is None else f"{host}:{port}"

    @property
    def endpoint_label(self) -> str:
        return self._endpoint_label

    def get_genesis_hash(self) -> str:
        try:
            response = self._client.get_genesis_hash()
        except Exception:
            raise SettlementRpcTransportError("get_genesis_hash_transport_failure") from None
        raw = getattr(response, "value", None)
        return self._canonical_hash(raw, "get_genesis_hash_response_invalid")

    def get_latest_blockhash(self) -> str:
        try:
            response = self._client.get_latest_blockhash(commitment=self._commitment)
        except Exception:
            raise SettlementRpcTransportError("get_latest_blockhash_transport_failure") from None
        value = getattr(response, "value", None)
        raw = getattr(value, "blockhash", None) if value is not None else None
        return self._canonical_hash(raw, "get_latest_blockhash_response_invalid")

    def simulate_transaction(self, transaction: VersionedTransaction) -> RpcSimulationResult:
        if not isinstance(transaction, VersionedTransaction):
            raise SettlementRpcResponseError("simulation_transaction_invalid")
        try:
            response = self._client.simulate_transaction(
                transaction,
                sig_verify=True,
                commitment=self._commitment,
                replace_recent_blockhash=False,
            )
        except Exception:
            raise SettlementRpcTransportError("simulate_transaction_transport_failure") from None
        value = getattr(response, "value", None)
        if value is None or not hasattr(value, "err") or not hasattr(value, "logs"):
            raise SettlementRpcResponseError("simulate_transaction_response_invalid")

        raw_logs = value.logs
        if raw_logs is None:
            logs: tuple[str, ...] = ()
        elif isinstance(raw_logs, (list, tuple)) and all(isinstance(item, str) for item in raw_logs):
            logs = tuple(raw_logs)
        else:
            raise SettlementRpcResponseError("simulate_transaction_logs_invalid")

        units = getattr(value, "units_consumed", None)
        if units is not None and (
            isinstance(units, bool) or not isinstance(units, int) or units < 0
        ):
            raise SettlementRpcResponseError("simulate_transaction_units_invalid")

        replacement = getattr(value, "replacement_blockhash", None)
        replacement_blockhash = None
        replacement_height = None
        if replacement is not None:
            raw_hash = getattr(replacement, "blockhash", None)
            raw_height = getattr(replacement, "last_valid_block_height", None)
            replacement_blockhash = self._canonical_hash(
                raw_hash, "simulate_transaction_replacement_blockhash_invalid"
            )
            if isinstance(raw_height, bool) or not isinstance(raw_height, int) or raw_height < 0:
                raise SettlementRpcResponseError(
                    "simulate_transaction_replacement_blockheight_invalid"
                )
            replacement_height = raw_height

        error = None if value.err is None else str(value.err)
        if error is not None and not error:
            raise SettlementRpcResponseError("simulate_transaction_error_invalid")
        return RpcSimulationResult(
            program_error=error,
            logs=logs,
            units_consumed=units,
            replacement_blockhash=replacement_blockhash,
            replacement_last_valid_block_height=replacement_height,
        )

    @staticmethod
    def _canonical_hash(value: object, error: str) -> str:
        try:
            text = str(value)
            parsed = Hash.from_string(text)
            if str(parsed) != text:
                raise ValueError
        except Exception as exc:
            raise SettlementRpcResponseError(error) from exc
        return text
