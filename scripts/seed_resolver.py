import os
import sys
import json
import argparse
import hashlib

def compute_resolver_hash(definition: dict) -> bytes:
    canonical_json = json.dumps(definition, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).digest()

def main():
    parser = argparse.ArgumentParser(description="Seed a resolver definition into the store.")
    parser.add_argument("file", help="Path to resolver definition JSON file")
    parser.add_argument("--store-dir", default="./resolver_store", help="Directory to store canonical JSON")
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

    # Create Store Dir
    os.makedirs(args.store_dir, exist_ok=True)
    
    # Write Canonical
    out_path = os.path.join(args.store_dir, f"{hash_hex}.json")
    with open(out_path, 'w') as f:
        # Canonical dump: sorted keys, compact separators
        json.dump(data, f, sort_keys=True, separators=(',', ':'))

    print(f"Resolver Seeded.")
    print(f"Hash: {hash_hex}")
    print(f"Path: {out_path}")

if __name__ == "__main__":
    main()
