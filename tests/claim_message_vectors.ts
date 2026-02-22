import { PublicKey } from "@solana/web3.js";
import { assert } from "chai";
import fs from "fs";
import path from "path";

type ClaimMessageVectors = {
  program_id: string;
  claim: string;
  notary_config: string;
  issuer: string;
  resolver_hash_hex: string;
  proof_hash_hex: string;
  public_inputs_hash_hex: string;
  claim_id: string;
  resolve_ts: number;
  outcome_idx: number;
  expected_claim_v1_len: number;
  expected_claim_v2_len: number;
  expected_claim_v1_hex: string;
  expected_claim_v2_hex: string;
};

const FIXTURE_PATH = path.join(__dirname, "fixtures", "claim_message_vectors.json");
const VECTORS = JSON.parse(
  fs.readFileSync(FIXTURE_PATH, "utf8")
) as ClaimMessageVectors;

function u64Le(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(value);
  return out;
}

function i64Le(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigInt64LE(value);
  return out;
}

function buildClaimMessageV1(v: ClaimMessageVectors): Buffer {
  return Buffer.concat([
    Buffer.from("PROPHET_CLAIM_RESOLVE_V1"),
    new PublicKey(v.program_id).toBuffer(),
    new PublicKey(v.claim).toBuffer(),
    Buffer.from(v.resolver_hash_hex, "hex"),
    new PublicKey(v.issuer).toBuffer(),
    u64Le(BigInt(v.claim_id)),
    i64Le(BigInt(v.resolve_ts)),
    Buffer.from([v.outcome_idx]),
    Buffer.from(v.proof_hash_hex, "hex"),
    Buffer.from(v.public_inputs_hash_hex, "hex"),
  ]);
}

function buildClaimMessageV2(v: ClaimMessageVectors): Buffer {
  return Buffer.concat([
    Buffer.from("PROPHET_CLAIM_RESOLVE_V2"),
    new PublicKey(v.program_id).toBuffer(),
    new PublicKey(v.claim).toBuffer(),
    new PublicKey(v.notary_config).toBuffer(),
    Buffer.from(v.resolver_hash_hex, "hex"),
    new PublicKey(v.issuer).toBuffer(),
    u64Le(BigInt(v.claim_id)),
    i64Le(BigInt(v.resolve_ts)),
    Buffer.from([v.outcome_idx]),
    Buffer.from(v.proof_hash_hex, "hex"),
    Buffer.from(v.public_inputs_hash_hex, "hex"),
  ]);
}

describe("prophet-claim-message-vectors", () => {
  it("matches fixed vector for claim resolve V1", () => {
    const msg = buildClaimMessageV1(VECTORS);
    assert.equal(msg.length, VECTORS.expected_claim_v1_len);
    assert.equal(msg.toString("hex"), VECTORS.expected_claim_v1_hex);
  });

  it("matches fixed vector for claim resolve V2", () => {
    const msg = buildClaimMessageV2(VECTORS);
    assert.equal(msg.length, VECTORS.expected_claim_v2_len);
    assert.equal(msg.toString("hex"), VECTORS.expected_claim_v2_hex);
  });
});
