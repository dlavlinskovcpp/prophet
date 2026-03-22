#!/usr/bin/env python3
import argparse
import sys

from src.config import settings
from src.signer_backend import _split_env_list
from src.signer_ops import bootstrap_aws_kms_keys, json_dumps, write_allowlist_file


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve AWS KMS Ed25519 keys into Prophet notary pubkeys."
    )
    parser.add_argument(
        "--region",
        default=settings.REMOTE_SIGNER_AWS_KMS_REGION,
        help="AWS region. Defaults to REMOTE_SIGNER_AWS_KMS_REGION.",
    )
    parser.add_argument(
        "--key-id",
        action="append",
        default=[],
        help="AWS KMS key id or alias. Repeat for multiple keys.",
    )
    parser.add_argument(
        "--endpoint-url",
        default=settings.REMOTE_SIGNER_AWS_KMS_ENDPOINT_URL,
        help="Optional AWS KMS endpoint override.",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=settings.REMOTE_SIGNER_AWS_KMS_TIMEOUT_S,
        help="KMS client timeout in seconds.",
    )
    parser.add_argument(
        "--output-allowlist",
        default="",
        help="Optional path to write a normalized signer allowlist file.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    key_ids = args.key_id or _split_env_list(settings.REMOTE_SIGNER_AWS_KMS_KEY_IDS)
    if not args.region.strip():
        print('{"ok": false, "error": "AWS region is required."}', file=sys.stderr)
        return 2
    if not key_ids:
        print('{"ok": false, "error": "At least one --key-id is required."}', file=sys.stderr)
        return 2

    try:
        payload = bootstrap_aws_kms_keys(
            region_name=args.region.strip(),
            key_ids=key_ids,
            endpoint_url=args.endpoint_url.strip(),
            timeout_s=args.timeout_s,
        )
        payload["ok"] = True
        if args.output_allowlist:
            payload["allowlist_written_to"] = args.output_allowlist
            payload["allowlist_pubkeys"] = write_allowlist_file(
                args.output_allowlist,
                payload["allowlist_pubkeys"],
            )
        print(json_dumps(payload))
        return 0
    except Exception as exc:
        print(json_dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
