import argparse
import base64
import json
from pathlib import Path
import urllib.request
import urllib.error


def _load_bytes(b64: str, raw: str, file_path: str) -> bytes:
    if b64:
        return base64.b64decode(b64)
    if file_path:
        return Path(file_path).read_bytes()
    if raw:
        return raw.encode()
    return b""

def _post_json(url: str, payload: dict, timeout_s: float = 15.0) -> tuple[int, str]:
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
    parser = argparse.ArgumentParser(
        description="Resolve a market through oracle-attester (threshold v2 by default; legacy requires attester compatibility flag)"
    )
    parser.add_argument("market", help="Market pubkey")
    parser.add_argument("outcome", choices=["YES", "NO", "INVALID"], help="Outcome to submit")
    parser.add_argument("--url", default="http://localhost:8000/resolve", help="Attester resolve URL")
    parser.add_argument("--proof-b64", default="", help="Base64 proof bytes")
    parser.add_argument("--proof-str", default="", help="Raw proof string (debug only)")
    parser.add_argument("--proof-file", default="", help="Proof file path")
    parser.add_argument("--pi-b64", default="", help="Base64 public inputs")
    parser.add_argument("--pi-str", default="", help="Raw public inputs string (usually JSON)")
    parser.add_argument("--pi-file", default="", help="Public inputs file path")
    parser.add_argument(
        "--proof-ref",
        default="",
        help="Optional proof_ref for attester fetcher (e.g. file:/abs/proof.bin:/abs/pi.json)",
    )
    args = parser.parse_args()

    proof_bytes = _load_bytes(args.proof_b64, args.proof_str, args.proof_file)
    pi_bytes = _load_bytes(args.pi_b64, args.pi_str, args.pi_file)

    proof_b64 = base64.b64encode(proof_bytes).decode() if proof_bytes else ""
    pi_b64 = base64.b64encode(pi_bytes).decode() if pi_bytes else ""

    payload = {
        "market": args.market,
        "outcome": args.outcome,
        "proof_bytes_b64": proof_b64,
        "public_inputs_bytes_b64": pi_b64,
        "proof_ref": args.proof_ref,
    }

    print(f"Submitting to {args.url}...")
    print(json.dumps(payload, indent=2))

    status, body = _post_json(args.url, payload, timeout_s=15.0)
    if status == 200:
        print("\nSuccess!")
        print(json.dumps(json.loads(body), indent=2))
    else:
        print(f"\nError {status}: {body}")

if __name__ == "__main__":
    main()
