import os
import base64
import httpx
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any
from .config import settings

@dataclass
class FetchedProof:
    proof_bytes: bytes
    public_inputs_bytes: bytes
    provider: str = ""
    meta: Optional[Dict[str, Any]] = None

class ProofFetcher(ABC):
    @abstractmethod
    def fetch(self, ref: str) -> FetchedProof:
        pass

class LocalFileProofFetcher(ProofFetcher):
    def fetch(self, ref: str) -> FetchedProof:
        """
        Expects ref in format 'file:<proof_path>:<pi_path>'
        """
        if not ref.startswith("file:"):
            raise ValueError("Local ref must start with file:")
        
        # Robust parsing allowing colons in paths if present later (Windows drive letters etc)
        # We assume exactly one separator between proof and pi path after prefix
        # But wait, split(":", 1) splits on first colon.
        # Format: file:path1:path2
        # We strip 'file:' (5 chars) then split once?
        # No, if paths have colons (e.g. C:\), simple split fails.
        # Requirement: "split once after removing the prefix"
        
        rest = ref[5:] # remove "file:"
        # We split on the LAST colon or FIRST?
        # The prompt requirement: "rest.split(':', 1)" means split on FIRST colon.
        # This implies proof_path cannot contain colons, but pi_path can.
        # Standard usage should avoid colons in filenames anyway on Linux/Mac.
        
        parts = rest.split(":", 1)
        if len(parts) < 2:
            raise ValueError("Invalid file ref format. Expected file:<proof>:<pi>")
            
        proof_path = parts[0]
        pi_path = parts[1]
        
        if not os.path.exists(proof_path):
            raise FileNotFoundError(f"Proof file missing: {proof_path}")
        if not os.path.exists(pi_path):
            raise FileNotFoundError(f"Public inputs file missing: {pi_path}")
            
        with open(proof_path, "rb") as f:
            proof = f.read()
        
        with open(pi_path, "rb") as f:
            pi = f.read()
            
        return FetchedProof(
            proof_bytes=proof,
            public_inputs_bytes=pi,
            provider="local_files",
            meta={
                "proof_path": proof_path, 
                "public_inputs_path": pi_path,
                "proof_size": len(proof),
                "pi_size": len(pi)
            }
        )

class HttpProofFetcher(ProofFetcher):
    def fetch(self, ref: str) -> FetchedProof:
        url = settings.PROOF_FETCH_URL
        if not url:
            raise ValueError("PROOF_FETCH_URL not configured")
            
        headers = {}
        if settings.PROOF_FETCH_API_KEY:
            headers["Authorization"] = f"Bearer {settings.PROOF_FETCH_API_KEY}"
            
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(url, params={"ref": ref}, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                
                # Support variant keys
                p_b64 = data.get("proof_bytes_b64") or data.get("proof_b64")
                pi_b64 = data.get("public_inputs_bytes_b64") or data.get("public_inputs_b64")
                
                if not p_b64 or not pi_b64:
                    raise ValueError("Response missing required b64 fields")
                    
                proof = base64.b64decode(p_b64)
                pi = base64.b64decode(pi_b64)
                
                # Strict scrub of base64 fields from meta
                scrub_keys = {
                    "proof_bytes_b64", "public_inputs_bytes_b64",
                    "proof_b64", "public_inputs_b64"
                }
                
                meta = {}
                for k, v in data.items():
                    if k in scrub_keys or k.endswith("_b64"):
                        continue
                    meta[k] = v
                    
                meta["ref"] = ref
                meta["status_code"] = resp.status_code
                
                return FetchedProof(
                    proof_bytes=proof,
                    public_inputs_bytes=pi,
                    provider="http_fetch",
                    meta=meta
                )
                
        except Exception as e:
            raise RuntimeError(f"HTTP fetch failed: {e}")

def make_fetcher() -> ProofFetcher:
    mode = settings.PROOF_FETCH_MODE.lower()
    if mode == "http":
        return HttpProofFetcher()
    return LocalFileProofFetcher()