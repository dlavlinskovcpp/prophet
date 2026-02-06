import os
import sys
import json
import base64
import argparse
import hashlib
import urllib.request
import urllib.error

def post_json(url: str, payload: dict, timeout_s: float = 15.0) -> tuple[int, str]:
    req = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body

def main():
    parser = argparse.ArgumentParser(description="End-to-End Resolve Runner")
    parser.add_argument("--market", required=True, help="Market Pubkey Base58")
    parser.add_argument("--attester-url", default="http://127.0.0.1:8000", help="Attester Service URL")
    
    # Mode A: Explicit Files
    parser.add_argument("--proof-file", help="Path to proof binary")
    parser.add_argument("--public-inputs-file", help="Path to public inputs (json/bin)")
    
    # Mode B: Ref Fetch
    parser.add_argument("--proof-ref", help="Reference ID for fetcher")
    
    args = parser.parse_args()

    from solders.pubkey import Pubkey

    # Ensure imports work for oracle-attester package modules (`src.*`)
    sys.path.append(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/oracle-attester"))
    )
    from src.solana_client import SolanaClient
    from src.config import settings
    from src.resolver import ResolverDefinition, evaluate_resolver, compute_resolver_hash
    from src.proof_fetcher import make_fetcher, FetchedProof
    from src.types import OutcomeEnum

    # 1. Fetch Chain State
    print(f"Fetching market {args.market}...")
    client = SolanaClient()
    market_pubkey = Pubkey.from_string(args.market)
    state = client.get_market_state_full(market_pubkey)
    
    if not state:
        print("Error: Market not found on-chain.")
        sys.exit(1)
        
    resolver_hash = state["resolver_hash"]
    resolver_hash_hex = resolver_hash.hex()
    
    if state["status"] == 2:
        print("Error: Market already resolved.")
        sys.exit(1)

    print(f"  Resolver Hash: {resolver_hash_hex}")
    print(f"  Open TS: {state['open_ts']}")

    # 2. Load Resolver Definition
    resolver_path = os.path.join(settings.RESOLVER_STORE_DIR, f"{resolver_hash_hex}.json")
    if not os.path.exists(resolver_path):
        print(f"Error: Resolver definition missing locally at {resolver_path}")
        sys.exit(1)
        
    with open(resolver_path, 'r') as f:
        res_data = json.load(f)
        
    # Verify Integrity
    if compute_resolver_hash(res_data) != resolver_hash:
        print("Error: Resolver definition integrity check failed (hash mismatch).")
        sys.exit(1)
        
    resolver_def = ResolverDefinition(**res_data)
    print(f"  Resolver Loaded: {resolver_def.url} ({resolver_def.predicate} {resolver_def.target_value})")

    # 3. Fetch Proof Artifacts
    if args.proof_file and args.public_inputs_file:
        # Direct file mode
        print("Loading proofs from local files...")
        with open(args.proof_file, 'rb') as f: p_bytes = f.read()
        with open(args.public_inputs_file, 'rb') as f: pi_bytes = f.read()
        proof_data = FetchedProof(proof_bytes=p_bytes, public_inputs_bytes=pi_bytes, provider="cli_files")
    elif args.proof_ref:
        # Fetcher mode
        print(f"Fetching proofs via ref: {args.proof_ref} (Mode: {settings.PROOF_FETCH_MODE})...")
        fetcher = make_fetcher()
        proof_data = fetcher.fetch(args.proof_ref)
    else:
        print("Error: Must provide either --proof-file/--public-inputs-file OR --proof-ref")
        sys.exit(1)

    p_len = len(proof_data.proof_bytes)
    pi_len = len(proof_data.public_inputs_bytes)
    p_hash = hashlib.sha256(proof_data.proof_bytes).hexdigest()
    pi_hash = hashlib.sha256(proof_data.public_inputs_bytes).hexdigest()
    
    print(f"  Proof Size: {p_len} bytes | Hash: {p_hash}")
    print(f"  PI Size:    {pi_len} bytes | Hash: {pi_hash}")

    # 4. Compute Outcome
    try:
        pi_json = json.loads(proof_data.public_inputs_bytes)
        if not isinstance(pi_json, dict):
            print("  Public Inputs not a JSON object -> INVALID")
            computed = OutcomeEnum.INVALID
        else:
            computed = evaluate_resolver(resolver_def, pi_json)
    except json.JSONDecodeError:
        print("  Public Inputs not valid JSON -> INVALID")
        computed = OutcomeEnum.INVALID
        
    print(f"  Computed Outcome: {computed}")

    # 5. Submit to Attester
    url = f"{args.attester_url}/resolve"
    payload = {
        "market": args.market,
        "outcome": computed.value, # Serialize enum to string explicitly
        "proof_bytes_b64": base64.b64encode(proof_data.proof_bytes).decode('utf-8'),
        "public_inputs_bytes_b64": base64.b64encode(proof_data.public_inputs_bytes).decode('utf-8')
    }
    
    print(f"Submitting to {url}...")
    try:
        status, body = post_json(url, payload, timeout_s=15.0)

        if status == 200:
            data = json.loads(body)
            print("\nSuccess!")
            print(f"  Tx Signature: {data.get('signature')}")
            print(f"  Resolved TS:  {data.get('resolved_ts')}")
            
            # Ensure no raw bytes printed
            scrubbed = {k: v for k, v in data.items() if not k.endswith("_b64")}
            print(f"  Response: {json.dumps(scrubbed, indent=2)}")
        else:
            print(f"\nError {status}:")
            print(body)
            sys.exit(1)
            
    except Exception as e:
        print(f"\nRequest Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
