import { createHash } from "crypto";

export const RESOLVER_V2_VERSION = "2.0.0";
export const RESOLVER_V2_SCHEMAS = {
  adapter: "prophet.adapter-descriptor.v2",
  trustModel: "prophet.trust-model-descriptor.v2",
  definition: "prophet.resolver-definition.v2",
  evidence: "prophet.evidence-envelope.v2",
  verification: "prophet.verification-result.v2",
  bundle: "prophet.resolution-bundle.v2",
} as const;

const DOMAINS: Record<string, Buffer> = {
  adapter: Buffer.from("PROPHET_ADAPTER_DESCRIPTOR_V2\0", "ascii"),
  trustModel: Buffer.from("PROPHET_TRUST_MODEL_V2\0", "ascii"),
  definition: Buffer.from("PROPHET_RESOLVER_DEFINITION_V2\0", "ascii"),
  evidence: Buffer.from("PROPHET_EVIDENCE_ENVELOPE_V2\0", "ascii"),
  verification: Buffer.from("PROPHET_VERIFICATION_RESULT_V2\0", "ascii"),
  bundle: Buffer.from("PROPHET_RESOLUTION_BUNDLE_V2\0", "ascii"),
};

const KEY = /^[a-z][a-z0-9_]*$/;
const UINT = /^(0|[1-9][0-9]*)$/;
const HEX32 = /^[0-9a-f]{64}$/;

export class ResolverV2Error extends Error {}

function fail(message: string): never { throw new ResolverV2Error(message); }

function canonicalValue(value: unknown): unknown {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number" || typeof value === "bigint") fail("numeric JSON values are forbidden");
  if (typeof value === "string") {
    if (value.normalize("NFC") !== value) fail("strings must be NFC-normalized");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (typeof value !== "object") fail("unsupported canonical value");
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    if (!KEY.test(key)) fail("object keys must be ASCII snake_case");
    result[key] = canonicalValue((value as Record<string, unknown>)[key]);
  }
  return result;
}

export function canonicalJsonBytes(payload: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify(canonicalValue(payload)), "utf8");
}

export function parseCanonicalJson(raw: Buffer): Record<string, unknown> {
  let parsed: unknown;
  try { parsed = JSON.parse(raw.toString("utf8")); } catch { fail("malformed canonical JSON"); }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) fail("payload must be an object");
  if (!canonicalJsonBytes(parsed as Record<string, unknown>).equals(raw)) fail("non-canonical JSON encoding");
  return parsed as Record<string, unknown>;
}

function schema(kind: keyof typeof RESOLVER_V2_SCHEMAS): string { return RESOLVER_V2_SCHEMAS[kind]; }

function validateHeader(payload: Record<string, unknown>, kind: keyof typeof RESOLVER_V2_SCHEMAS): void {
  if (payload.schema !== schema(kind) || payload.schema_version !== RESOLVER_V2_VERSION) fail("unsupported schema version");
}

function hex(value: unknown, field: string): string {
  if (typeof value !== "string" || !HEX32.test(value)) fail(`${field} must be lowercase bytes32 hex`);
  return value;
}

function uint(value: unknown, field: string): string {
  if (typeof value !== "string" || !UINT.test(value) || BigInt(value) > 0xffff_ffff_ffff_ffffn) fail(`${field} must be a u64 decimal string`);
  return value;
}

function hash(kind: keyof typeof RESOLVER_V2_SCHEMAS, payload: Record<string, unknown>): string {
  validateHeader(payload, kind);
  const schemaBytes = Buffer.from(schema(kind), "ascii");
  const versionBytes = Buffer.from(RESOLVER_V2_VERSION, "ascii");
  const body = canonicalJsonBytes(payload);
  const frame = Buffer.concat([
    DOMAINS[kind], Buffer.from([schemaBytes.length & 0xff, schemaBytes.length >> 8]), schemaBytes,
    Buffer.from([versionBytes.length & 0xff, versionBytes.length >> 8]), versionBytes,
    Buffer.from([body.length & 0xff, (body.length >>> 8) & 0xff, (body.length >>> 16) & 0xff, (body.length >>> 24) & 0xff]), body,
  ]);
  return createHash("sha256").update(frame).digest("hex");
}

export const adapterDigest = (payload: Record<string, unknown>) => hash("adapter", payload);
export const trustModelDigest = (payload: Record<string, unknown>) => hash("trustModel", payload);
export const resolverDefinitionHash = (payload: Record<string, unknown>) => hash("definition", payload);
export const evidenceHash = (payload: Record<string, unknown>) => hash("evidence", payload);
export const verificationResultHash = (payload: Record<string, unknown>) => hash("verification", payload);
export const resolutionBundleHash = (payload: Record<string, unknown>) => hash("bundle", payload);

export function validateResolutionBundle(payload: Record<string, unknown>, nowMs?: bigint): void {
  validateHeader(payload, "bundle");
  for (const field of ["market", "resolver_definition_hash", "trust_model_digest", "cluster_genesis_hash", "settlement_program_id", "notary_config", "resolution_nonce"]) hex(payload[field], field);
  const definition = payload.resolver_definition as Record<string, unknown>;
  if (!definition || resolverDefinitionHash(definition) !== payload.resolver_definition_hash) fail("resolver binding mismatch");
  const trust = payload.trust_model as Record<string, unknown>;
  if (!trust || trustModelDigest(trust) !== payload.trust_model_digest) fail("trust-model binding mismatch");
  const evidence = payload.evidence;
  const verification = payload.verification_results;
  if (!Array.isArray(evidence) || !Array.isArray(verification) || evidence.length === 0 || verification.length === 0) fail("bundle requires evidence and verification results");
  const ids = new Set<string>();
  const evidenceHashes = new Set<string>();
  let lastId = "";
  for (const item of evidence as Record<string, unknown>[]) {
    validateHeader(item, "evidence");
    const id = hex(item.evidence_id, "evidence_id");
    if (ids.has(id) || id <= lastId) fail("duplicate or unordered evidence IDs");
    if (item.definition_hash !== payload.resolver_definition_hash) fail("inconsistent evidence resolver binding");
    ids.add(id); lastId = id; evidenceHashes.add(evidenceHash(item));
  }
  let lastResult = "";
  for (const item of verification as Record<string, unknown>[]) {
    validateHeader(item, "verification");
    if (item.definition_hash !== payload.resolver_definition_hash || !evidenceHashes.has(String(item.evidence_hash))) fail("inconsistent verification binding");
    const resultHash = verificationResultHash(item);
    if (resultHash <= lastResult) fail("verification results must be sorted");
    lastResult = resultHash;
    if (nowMs !== undefined && BigInt(uint(item.valid_until_ms, "valid_until_ms")) < nowMs) fail("stale verification result");
  }
  if (nowMs !== undefined && BigInt(uint(payload.valid_until_ms, "valid_until_ms")) < nowMs) fail("stale bundle");
}
