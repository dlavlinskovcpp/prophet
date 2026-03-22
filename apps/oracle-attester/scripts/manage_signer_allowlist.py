#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

from src.config import settings
from src.signer_ops import (
    allowlist_snapshot,
    json_dumps,
    merge_allowlist_entries,
    normalize_pubkeys,
    read_pubkeys_file,
    write_allowlist_file,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect or atomically update a Prophet signer allowlist file."
    )
    parser.add_argument(
        "--path",
        default=settings.REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH,
        help="Allowlist path. Defaults to REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("show", help="Print the normalized allowlist.")

    for name in ("replace", "add", "remove"):
        subparser = subparsers.add_parser(name, help=f"{name.capitalize()} allowlist entries.")
        subparser.add_argument(
            "--public-key",
            action="append",
            default=[],
            help="Signer pubkey. Repeat for multiple values.",
        )
        subparser.add_argument(
            "--pubkeys-file",
            default="",
            help="Optional newline/comma-delimited file of signer pubkeys.",
        )
        subparser.add_argument(
            "--allow-empty",
            action="store_true",
            help="Allow the resulting allowlist file to be empty.",
        )

    return parser.parse_args()


def requested_pubkeys(args: argparse.Namespace):
    entries = list(getattr(args, "public_key", []) or [])
    path = getattr(args, "pubkeys_file", "")
    if path:
        entries.extend(read_pubkeys_file(path))
    return normalize_pubkeys(entries)


def ensure_nonempty(entries, *, allow_empty: bool) -> None:
    if entries or allow_empty:
        return
    raise ValueError("Refusing to write an empty allowlist without --allow-empty.")


def main() -> int:
    args = parse_args()
    if not args.path.strip():
        print('{"ok": false, "error": "Allowlist path is required."}', file=sys.stderr)
        return 2

    try:
        exists = Path(args.path).exists()
        if args.command == "show":
            entries = allowlist_snapshot(args.path) if exists else []
            print(
                json_dumps(
                    {
                        "ok": True,
                        "command": "show",
                        "path": args.path,
                        "exists": exists,
                        "count": len(entries),
                        "entries": entries,
                    }
                )
            )
            return 0

        current = allowlist_snapshot(args.path) if exists else []
        requested = requested_pubkeys(args)

        if args.command == "replace":
            next_entries = requested
        elif args.command == "add":
            next_entries = merge_allowlist_entries(current, additions=requested)
        else:
            next_entries = merge_allowlist_entries(current, removals=requested)

        ensure_nonempty(next_entries, allow_empty=bool(args.allow_empty))
        written = write_allowlist_file(args.path, next_entries)
        print(
            json_dumps(
                {
                    "ok": True,
                    "command": args.command,
                    "path": args.path,
                    "changed": written != current,
                    "previous_count": len(current),
                    "count": len(written),
                    "entries": written,
                }
            )
        )
        return 0
    except Exception as exc:
        print(json_dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
