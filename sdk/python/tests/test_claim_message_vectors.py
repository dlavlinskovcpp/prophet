import json
from pathlib import Path

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from prophet_sdk.client import ProphetClient
from prophet_sdk.types import ClaimOutcome

FIXTURE_PATH = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "claim_message_vectors.json"
VECTORS = json.loads(FIXTURE_PATH.read_text())

PROGRAM_ID = Pubkey.from_string(VECTORS["program_id"])
CLAIM = Pubkey.from_string(VECTORS["claim"])
NOTARY_CONFIG = Pubkey.from_string(VECTORS["notary_config"])
ISSUER = Pubkey.from_string(VECTORS["issuer"])

RESOLVER_HASH = bytes.fromhex(VECTORS["resolver_hash_hex"])
PROOF_HASH = bytes.fromhex(VECTORS["proof_hash_hex"])
PUBLIC_INPUTS_HASH = bytes.fromhex(VECTORS["public_inputs_hash_hex"])
CLAIM_ID = int(VECTORS["claim_id"])
RESOLVE_TS = int(VECTORS["resolve_ts"])
OUTCOME_IDX = int(VECTORS["outcome_idx"])

EXPECTED_CLAIM_V1_LEN = int(VECTORS["expected_claim_v1_len"])
EXPECTED_CLAIM_V2_LEN = int(VECTORS["expected_claim_v2_len"])
EXPECTED_CLAIM_V1_HEX = VECTORS["expected_claim_v1_hex"]
EXPECTED_CLAIM_V2_HEX = VECTORS["expected_claim_v2_hex"]


def _make_client(tmp_path) -> ProphetClient:
    payer = Keypair()
    payer_path = tmp_path / "payer.json"
    payer_path.write_text(json.dumps(list(bytes(payer))))
    return ProphetClient(
        rpc_url="http://127.0.0.1:8899",
        payer_keypair_path=str(payer_path),
        program_id=str(PROGRAM_ID),
    )


def test_claim_message_v1_fixed_vector(tmp_path):
    assert OUTCOME_IDX == 1
    client = _make_client(tmp_path)
    msg = client._build_claim_resolve_message_v1(
        claim=CLAIM,
        resolver_hash=RESOLVER_HASH,
        issuer=ISSUER,
        claim_id=CLAIM_ID,
        resolve_ts=RESOLVE_TS,
        outcome=ClaimOutcome.Pass,
        proof_hash=PROOF_HASH,
        public_inputs_hash=PUBLIC_INPUTS_HASH,
    )
    assert len(msg) == EXPECTED_CLAIM_V1_LEN
    assert msg.hex() == EXPECTED_CLAIM_V1_HEX


def test_claim_message_v2_fixed_vector(tmp_path):
    assert OUTCOME_IDX == 1
    client = _make_client(tmp_path)
    msg = client._build_claim_resolve_message_v2(
        claim=CLAIM,
        notary_config=NOTARY_CONFIG,
        resolver_hash=RESOLVER_HASH,
        issuer=ISSUER,
        claim_id=CLAIM_ID,
        resolve_ts=RESOLVE_TS,
        outcome=ClaimOutcome.Pass,
        proof_hash=PROOF_HASH,
        public_inputs_hash=PUBLIC_INPUTS_HASH,
    )
    assert len(msg) == EXPECTED_CLAIM_V2_LEN
    assert msg.hex() == EXPECTED_CLAIM_V2_HEX
