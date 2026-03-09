import os
import sys
import json
import argparse
import hashlib
import urllib.request
import urllib.error

def compute_resolver_hash(definition: dict) -> bytes:
    canonical_json = json.dumps(definition, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).digest()

def main():
    parser = argparse.ArgumentParser(description="Seed a resolver definition into the store.")
    parser.add_argument("file", help="Path to resolver definition JSON file")
    parser.add_argument("--store-dir", default="./resolver_store", help="Directory to store canonical JSON")
    parser.add_argument("--registry-url", default="", help="HTTP resolver registry publish endpoint")
    parser.add_argument("--api-key", default="", help="Bearer token for HTTP registry publish")
    parser.add_argument("--timeout-s", type=float, default=5.0, help="HTTP publish timeout seconds")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)

    try:
        with open(args.file, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}")
        sys.exit(1)

    # Compute Hash
    resolver_hash = compute_resolver_hash(data)
    hash_hex = resolver_hash.hex()

    if args.registry_url:
        payload = json.dumps(
            {"resolver": data, "expected_hash": hash_hex},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if args.api_key:
            headers["Authorization"] = f"Bearer {args.api_key}"

        req = urllib.request.Request(
            args.registry_url,
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=args.timeout_s) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            print(f"Error: Registry returned HTTP {e.code}: {detail}")
            sys.exit(1)
        except Exception as e:
            print(f"Error: Registry publish failed: {e}")
            sys.exit(1)

        print("Resolver Published.")
        print(f"Hash: {hash_hex}")
        print(f"Registry: {args.registry_url}")
        if body:
            print(f"Response: {body}")
        return

    # Create Store Dir
    os.makedirs(args.store_dir, exist_ok=True)

    # Write Canonical
    out_path = os.path.join(args.store_dir, f"{hash_hex}.json")
    with open(out_path, 'w') as f:
        # Canonical dump: sorted keys, compact separators
        json.dump(data, f, sort_keys=True, separators=(',', ':'))

    print("Resolver Seeded.")
    print(f"Hash: {hash_hex}")
    print(f"Path: {out_path}")

if __name__ == "__main__":
    main()
