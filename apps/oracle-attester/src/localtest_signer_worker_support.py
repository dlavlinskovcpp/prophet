"""Private, localtest-only support used by the two fixed worker scripts.

The public executable identities live in ``localtest_signer_a_worker.py`` and
``localtest_signer_b_worker.py``.  This helper never receives a role from an
HTTP request, environment variable, or command-line argument.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import uvicorn

from .admission_grant_replay_journal import AdmissionGrantReplayJournal
from .independent_signer_execution import IndependentSignerEngine, IndependentSignerVaultAdapter
from .independent_signer_journal import IndependentSignerBinding, IndependentSignerJournal
from .independent_signer_runtime import IndependentSignerServiceConfig
from .localtest_file_vault_transport import LocaltestFileVaultTransport
from .localtest_solana_finalized_rpc import LocaltestSolanaFinalizedRpc
from .signer_admission_grant import AdmissionGrantContext, AdmissionIssuerKeyV1
from .signer_admission_runtime import SignerAdmissionRuntime
from .signer_authorization import Account, FinalizedAccountRead, FinalizedAccountsRead, SignerAuthorizationConfig, VerifierPin


class LocaltestSignerWorkerError(RuntimeError):
    pass


def _json_file(path: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise LocaltestSignerWorkerError("localtest_worker_config_invalid") from exc
    if not isinstance(value, dict):
        raise LocaltestSignerWorkerError("localtest_worker_config_invalid")
    return value


def _state_directory(path: str) -> Path:
    value = Path(path)
    if not value.is_absolute():
        raise LocaltestSignerWorkerError("localtest_worker_state_path_invalid")
    value.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = value.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode) or details.st_mode & 0o077:
        raise LocaltestSignerWorkerError("localtest_worker_state_path_invalid")
    return value.resolve(strict=True)


def _require_disjoint(*paths: Path) -> None:
    canonical = [path.resolve(strict=False) for path in paths]
    if len(set(canonical)) != len(canonical):
        raise LocaltestSignerWorkerError("localtest_worker_state_path_alias")


class _FixtureFinalizedRpc:
    """Localtest-only finalized snapshot adapter; it never contacts a network."""

    def __init__(self, value: Mapping[str, Any]) -> None:
        if not isinstance(value, Mapping):
            raise LocaltestSignerWorkerError("localtest_rpc_fixture_invalid")
        try:
            self._genesis = value["genesis_hash"]
            self._slot = value["finalized_slot"]
            self._block_time = value["block_time"]
            self._accounts = {
                key: Account(row["owner"], bytes.fromhex(row["data_hex"]))
                for key, row in value["accounts"].items()
            }
        except Exception as exc:
            raise LocaltestSignerWorkerError("localtest_rpc_fixture_invalid") from exc
        if isinstance(self._slot, bool) or not isinstance(self._slot, int) or self._slot < 0:
            raise LocaltestSignerWorkerError("localtest_rpc_fixture_invalid")

    def genesis_hash(self) -> str: return self._genesis
    def finalized_slot(self) -> int: return self._slot
    def block_time(self, slot: int) -> int | None: return self._block_time if slot == self._slot else None
    def finalized_account(self, pubkey: str, *, min_context_slot: int) -> FinalizedAccountRead:
        return FinalizedAccountRead(self._accounts.get(pubkey), self._slot)
    def finalized_accounts(self, pubkeys: tuple[str, str], *, min_context_slot: int) -> FinalizedAccountsRead:
        return FinalizedAccountsRead({key: self._accounts.get(key) for key in pubkeys}, self._slot)


def _rpc(raw: Mapping[str, Any]) -> Any:
    """Select an explicitly declared localtest RPC mode; never fall back silently."""
    mode = raw.get("localtest_rpc_mode")
    if mode == "real-local-validator-finalized":
        endpoint = raw.get("localtest_rpc_url")
        return LocaltestSolanaFinalizedRpc(
            endpoint,
            environment="localtest",
            mode="test",
            topology_classification="FUNCTIONAL_TEST_ONLY",
        )
    if mode == "fixture":
        return _FixtureFinalizedRpc(raw["rpc_fixture"])
    # Retain the pre-existing unit-test-only fixture lane.  Real workers must
    # declare the explicit mode above; no production parser reaches this code.
    if mode is None and "rpc_fixture" in raw:
        return _FixtureFinalizedRpc(raw["rpc_fixture"])
    raise LocaltestSignerWorkerError("localtest_rpc_mode_required")


def _service_config(raw: Mapping[str, Any], *, role: str, public_key: str) -> tuple[IndependentSignerServiceConfig, Mapping[str, Any]]:
    try:
        value = dict(raw["service"])
        # Production-shaped config retains this historical field, but the
        # localtest fixed-role application is grant-only.  Normalize its
        # absence here, after the localtest-only preflight and before the
        # immutable production parser sees the fixture.  No value is read and
        # no admission path is enabled by this compatibility normalization.
        if "admission_token_env" not in value:
            value["admission_token_env"] = f"LOCALTEST_INTERNAL_{role}_UNUSED"
        signer = dict(value["signer"])
        signer["role"] = role
        signer["public_key"] = public_key
        signer["key_version"] = 1
        value["signer"] = signer
        config = IndependentSignerServiceConfig.from_mapping(value)
    except Exception as exc:
        raise LocaltestSignerWorkerError("localtest_worker_service_config_invalid") from exc
    if config.environment != "localtest" or config.mode != "test" or config.topology_classification != "FUNCTIONAL_TEST_ONLY" or config.signer_role != role:
        raise LocaltestSignerWorkerError("localtest_worker_environment_rejected")
    return config, value


def _preflight_localtest_service(raw: Mapping[str, Any], *, role: str) -> tuple[str, str]:
    """Reject non-localtest service input before any signer file is touched."""
    try:
        service, signer, vault = raw["service"], raw["service"]["signer"], raw["service"]["vault"]
        if not isinstance(service, Mapping) or not isinstance(signer, Mapping) or not isinstance(vault, Mapping):
            raise ValueError
        if service["environment"] != "localtest" or service["mode"] != "test" or service["topology_classification"] != "FUNCTIONAL_TEST_ONLY" or signer["role"] != role:
            raise ValueError
        signer_id, key_name = signer["signer_id"], vault["key_name"]
        if not isinstance(signer_id, str) or not signer_id or not isinstance(key_name, str) or not key_name:
            raise ValueError
    except Exception as exc:
        raise LocaltestSignerWorkerError("localtest_worker_environment_rejected") from exc
    return signer_id, key_name


def _authorization(raw: Mapping[str, Any], *, role: str, public_key: str, config: IndependentSignerServiceConfig) -> SignerAuthorizationConfig:
    try:
        value = raw["authorization"]
        verifier_a = VerifierPin(**value["verifier_a"])
        verifier_b = VerifierPin(**value["verifier_b"])
        counterpart = value["counterpart_notary_public_key"]
    except Exception as exc:
        raise LocaltestSignerWorkerError("localtest_worker_authorization_config_invalid") from exc
    return SignerAuthorizationConfig(role, public_key, counterpart, verifier_a, verifier_b, config.expected_genesis_hash, config.expected_program_id)


def _admission(raw: Mapping[str, Any], *, role: str, config: IndependentSignerServiceConfig, replay_path: Path) -> SignerAdmissionRuntime:
    try:
        value = raw["admission"]
        context = AdmissionGrantContext(role, config.signer_id, "localtest", value["git_sha"], value["evidence_set_id"], value["acceptance_run_id"])
        key = AdmissionIssuerKeyV1(value["key_id"], value["issuer_id"], role, value["issuer_public_key"], value["valid_from"], value["valid_until"])
    except Exception as exc:
        raise LocaltestSignerWorkerError("localtest_worker_admission_config_invalid") from exc
    return SignerAdmissionRuntime(context, (key,), AdmissionGrantReplayJournal(replay_path, signer_role=role), lambda: datetime.now(timezone.utc))


def _write_readiness(path: Path, *, role: str, signer_service_id: str, endpoint: str, signer_public_key: str) -> None:
    value = {"schema": "PROPHET_LOCALTEST_SIGNER_READINESS_V1", "version": 1, "role": role, "signer_service_id": signer_service_id, "endpoint": endpoint, "signer_public_key": signer_public_key, "pid": os.getpid(), "ready": True}
    descriptor, temporary = tempfile.mkstemp(prefix=".readiness-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":")); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def _remove_stale_readiness(path: Path) -> None:
    if not path.exists():
        return
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        pid = value["pid"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError
        os.kill(pid, 0)
    except ProcessLookupError:
        path.unlink()
    except PermissionError as exc:
        raise LocaltestSignerWorkerError("localtest_worker_existing_process_ambiguous") from exc
    except Exception:
        # A malformed file has no authenticated liveness claim and can safely
        # be replaced only after its directory has passed the strict checks.
        path.unlink()
    else:
        raise LocaltestSignerWorkerError("localtest_worker_already_running")


async def _serve(app: Any, listener: socket.socket, readiness: Path, *, role: str, service_id: str, public_key: str) -> None:
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", workers=1, reload=False))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    for _ in range(500):
        if server.started: break
        if task.done(): await task; raise LocaltestSignerWorkerError("localtest_worker_listener_failed")
        await asyncio.sleep(0.01)
    if not server.started: raise LocaltestSignerWorkerError("localtest_worker_listener_timeout")
    _write_readiness(readiness, role=role, signer_service_id=service_id, endpoint=f"http://127.0.0.1:{port}", signer_public_key=public_key)
    await task


def run_fixed_localtest_worker(*, fixed_role: str, application_factory: Any, argv: list[str] | None = None) -> None:
    if fixed_role not in {"A", "B"}:
        raise LocaltestSignerWorkerError("localtest_worker_fixed_role_invalid")
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--bootstrap-file", required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        raise LocaltestSignerWorkerError("localtest_worker_port_invalid")
    state = _state_directory(args.state_dir)
    seed_path, replay_path, journal_path, readiness_path = (state / "signer.seed", state / "admission-replay.sqlite3", state / "independent-signer.sqlite3", state / "readiness.json")
    _require_disjoint(seed_path, replay_path, journal_path, readiness_path)
    _remove_stale_readiness(readiness_path)
    raw = _json_file(args.bootstrap_file)
    signer_id, vault_key_name = _preflight_localtest_service(raw, role=fixed_role)
    # The raw public configuration is fail-closed before any signer seed is
    # opened; the transport repeats the same localtest guard in depth.
    transport = LocaltestFileVaultTransport(environment="localtest", mode="test", signer_role=fixed_role, signer_id=signer_id, vault_key_name=vault_key_name, key_version=1, seed_path=seed_path, initialize=not seed_path.exists())
    config, application_config = _service_config(raw, role=fixed_role, public_key=transport.public_key)
    if config.signer_id != transport.signer_id or config.vault_key_name != transport.vault_key_name:
        raise LocaltestSignerWorkerError("localtest_worker_transport_binding_invalid")
    authorization = _authorization(raw, role=fixed_role, public_key=transport.public_key, config=config)
    admission = _admission(raw, role=fixed_role, config=config, replay_path=replay_path)
    journal = IndependentSignerJournal(journal_path, binding=IndependentSignerBinding(fixed_role, config.signer_id, transport.public_key, 1))
    adapter = IndependentSignerVaultAdapter(config, transport=transport)
    engine = IndependentSignerEngine(service_config=config, authorization_config=authorization, journal=journal, rpc=_rpc(raw), vault=adapter)
    app = application_factory(application_config, admission_factory=lambda _: admission, engine_factory=lambda _: engine)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0); listener.bind(("127.0.0.1", args.port)); listener.listen(32)
    try:
        asyncio.run(_serve(app, listener, readiness_path, role=fixed_role, service_id=config.signer_id, public_key=transport.public_key))
    finally:
        journal.close(); adapter.close()
