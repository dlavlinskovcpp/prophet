import { assert } from "chai";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import {
  adapterDigest, canonicalJsonBytes, evidenceHash, parseCanonicalJson,
  resolutionBundleHash, resolverDefinitionHash, trustModelDigest,
  validateResolutionBundle, verificationResultHash, ResolverV2Error,
} from "./support/resolver_v2";

describe("resolver-v2 canonical vectors", () => {
  const vectorPath = path.resolve(__dirname, "../resolver-v2/test-vectors/v2.json");
  const vector = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
  const bundle = vector.bundle_payload;
  const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value));

  it("matches permanent cross-language hashes", () => {
    assert.equal(adapterDigest(bundle.verifier), vector.hashes.adapter);
    assert.equal(trustModelDigest(bundle.trust_model), vector.hashes.trust_model);
    assert.equal(resolverDefinitionHash(bundle.resolver_definition), vector.hashes.definition);
    assert.deepEqual(bundle.evidence.map(evidenceHash), vector.hashes.evidence);
    assert.deepEqual(bundle.verification_results.map(verificationResultHash), vector.hashes.verification);
    assert.equal(resolutionBundleHash(bundle), vector.hashes.bundle);
    validateResolutionBundle(bundle, 2000n);
  });

  it("is canonical under reordered object fields and rejects non-canonical bytes", () => {
    const reordered = { schema_version: bundle.resolver_definition.schema_version, schema: bundle.resolver_definition.schema, resolver_type: bundle.resolver_definition.resolver_type, resolver_id: bundle.resolver_definition.resolver_id, adapter: bundle.resolver_definition.adapter, trust_model: bundle.resolver_definition.trust_model, source: bundle.resolver_definition.source, verification_policy: bundle.resolver_definition.verification_policy, evaluation: bundle.resolver_definition.evaluation, timing: bundle.resolver_definition.timing, conflict_policy: bundle.resolver_definition.conflict_policy, fallback_policy: bundle.resolver_definition.fallback_policy };
    assert.equal(resolverDefinitionHash(reordered), vector.hashes.definition);
    assert.throws(() => parseCanonicalJson(Buffer.from('{ "schema":"x" }')), ResolverV2Error);
    assert.throws(() => canonicalJsonBytes({ number: 1 }), ResolverV2Error);
    assert.throws(() => canonicalJsonBytes({ text: "Cafe\u0301" }), ResolverV2Error);
  });

  it("rejects replay and binding violations", () => {
    const duplicate = copy(bundle);
    duplicate.evidence[1].evidence_id = duplicate.evidence[0].evidence_id;
    assert.throws(() => validateResolutionBundle(duplicate), ResolverV2Error);
    const stale = copy(bundle);
    stale.valid_until_ms = "1999";
    assert.throws(() => validateResolutionBundle(stale, 2000n), ResolverV2Error);
    assert.notEqual(vector.hashes.definition, vector.hashes.bundle);
    assert.notEqual(resolutionBundleHash(bundle), createHash("sha256").update(canonicalJsonBytes(bundle)).digest("hex"));
  });
});
