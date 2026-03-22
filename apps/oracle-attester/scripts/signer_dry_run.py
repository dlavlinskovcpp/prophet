#!/usr/bin/env python3
import argparse
import base64
import hashlib
import sys
from typing import List

from src.config import settings
from src.signer_allowlist import make_signer_allowlist
from src.signer_backend import make_remote_signer_backend
from src.signer_ops import (
    build_dry_run_message,
    discover_pubkeys_from_signer_health,
    fetch_remote_signer_health,
    json_dumps,
    normalize_pubkeys,
    parse_message_b64,
    read_pubkeys_file,
    request_remote_signer_signature,
    run_backend_dry_run,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a Prophet remote-signer dry-run against the backend or HTTP service."
    )
    parser.add_argument(
        "--label",
        default="default",
        help="Human-readable label included in the dry-run message context.",
    )
    parser.add_argument(
        "--message-b64",
        default="",
        help="Optional explicit base64 message payload. Overrides --label.",
    )
    parser.add_argument(
        "--public-key",
        action="append",
        default=[],
        help="Signer pubkey to test. Repeat for multiple pubkeys.",
    )
    parser.add_argument(
        "--pubkeys-file",
        default="",
        help="Optional newline/comma-delimited file of signer pubkeys to test.",
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    backend = subparsers.add_parser("backend", help="Sign directly through the configured backend.")
    backend.add_argument(
        "--skip-allowlist-check",
        action="store_true",
        help="Skip allowlist readiness and membership checks.",
    )

    service = subparsers.add_parser("service", help="Sign through the remote signer HTTP API.")
    service.add_argument(
        "--url",
        default=settings.REMOTE_SIGNER_URL,
        help="Remote signer sign URL or base URL. Defaults to REMOTE_SIGNER_URL.",
    )
    service.add_argument(
        "--health-url",
        default="",
        help="Optional health endpoint override. Defaults to /health next to the sign URL.",
    )
    service.add_argument(
        "--api-key",
        default=settings.REMOTE_SIGNER_API_KEY,
        help="Bearer token for /sign. Defaults to REMOTE_SIGNER_API_KEY.",
    )
    service.add_argument(
        "--timeout-s",
        type=float,
        default=settings.REMOTE_SIGNER_TIMEOUT_S,
        help="HTTP timeout in seconds.",
    )

    return parser.parse_args()


def selected_pubkeys(args: argparse.Namespace) -> List[str]:
    items = list(args.public_key)
    if args.pubkeys_file:
        items.extend(read_pubkeys_file(args.pubkeys_file))
    return normalize_pubkeys(items)


def main() -> int:
    args = parse_args()

    try:
        message = (
            parse_message_b64(args.message_b64)
            if args.message_b64
            else build_dry_run_message(args.label)
        )
        context = {"operation": "dry_run", "label": str(args.label)}
        requested_pubkeys = selected_pubkeys(args)

        if args.mode == "backend":
            settings.validate_remote_signer_service_runtime()
            backend = make_remote_signer_backend()
            allowlist = make_signer_allowlist()
            allowlist_health = allowlist.health()

            if not args.skip_allowlist_check:
                if not allowlist_health.get("allowlist_ready", True):
                    raise RuntimeError("Signer allowlist is not ready.")
                check_pubkeys = requested_pubkeys or backend.loaded_pubkeys()
                for pubkey in check_pubkeys:
                    if not allowlist.contains(pubkey):
                        raise RuntimeError(f"Signer {pubkey} is not present in the signer allowlist.")

            payload = run_backend_dry_run(
                backend,
                public_keys=requested_pubkeys,
                message=message,
                context=context,
            )
            payload.update(
                {
                    "ok": True,
                    "mode": "backend",
                    "backend_health": backend.health(),
                    "allowlist_health": allowlist_health,
                }
            )
            print(json_dumps(payload))
            return 0

        if not args.url.strip():
            raise ValueError("Remote signer URL is required for service mode.")

        health = fetch_remote_signer_health(
            args.url,
            timeout_s=args.timeout_s,
            health_url=args.health_url,
        )
        if not health.get("ok", True):
            raise RuntimeError("Remote signer health reported not ok.")

        check_pubkeys = requested_pubkeys or discover_pubkeys_from_signer_health(health)
        if not check_pubkeys:
            raise ValueError(
                "No signer public keys provided and remote signer health did not expose loaded signer keys."
            )

        results = [
            request_remote_signer_signature(
                args.url,
                public_key=pubkey,
                message=message,
                context=context,
                timeout_s=args.timeout_s,
                api_key=args.api_key,
            )
            for pubkey in check_pubkeys
        ]
        payload = {
            "ok": True,
            "mode": "service",
            "message_b64": base64.b64encode(message).decode("ascii"),
            "message_len": len(message),
            "message_sha256": hashlib.sha256(message).hexdigest(),
            "health": health,
            "results": results,
        }
        print(json_dumps(payload))
        return 0
    except Exception as exc:
        print(json_dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
