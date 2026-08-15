//! Resolver V2.0 canonical serialization and hash conformance library.
//! This crate is host-only and has no dependency on the on-chain program.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub const VERSION: &str = "2.0.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    NonCanonical,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub enum Kind {
    Adapter,
    TrustModel,
    Definition,
    Evidence,
    Verification,
    Bundle,
}

impl Kind {
    pub fn schema(self) -> &'static str {
        match self {
            Self::Adapter => "prophet.adapter-descriptor.v2",
            Self::TrustModel => "prophet.trust-model-descriptor.v2",
            Self::Definition => "prophet.resolver-definition.v2",
            Self::Evidence => "prophet.evidence-envelope.v2",
            Self::Verification => "prophet.verification-result.v2",
            Self::Bundle => "prophet.resolution-bundle.v2",
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::Adapter => b"PROPHET_ADAPTER_DESCRIPTOR_V2\0",
            Self::TrustModel => b"PROPHET_TRUST_MODEL_V2\0",
            Self::Definition => b"PROPHET_RESOLVER_DEFINITION_V2\0",
            Self::Evidence => b"PROPHET_EVIDENCE_ENVELOPE_V2\0",
            Self::Verification => b"PROPHET_VERIFICATION_RESULT_V2\0",
            Self::Bundle => b"PROPHET_RESOLUTION_BUNDLE_V2\0",
        }
    }
}

fn valid_key(key: &str) -> bool {
    let mut chars = key.bytes();
    matches!(chars.next(), Some(b'a'..=b'z'))
        && chars.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn canonical_value(value: &Value) -> Result<Value> {
    match value {
        Value::Null | Value::Bool(_) => Ok(value.clone()),
        Value::Number(_) => Err(Error::Invalid("numeric JSON values are forbidden")),
        Value::String(value) => {
            if value.nfc().collect::<String>() != *value {
                return Err(Error::Invalid("strings must be NFC-normalized"));
            }
            Ok(value.clone().into())
        }
        Value::Array(values) => values
            .iter()
            .map(canonical_value)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(values) => {
            let mut canonical = Map::new();
            for (key, value) in values {
                if !valid_key(key) {
                    return Err(Error::Invalid("keys must be ASCII snake_case"));
                }
                canonical.insert(key.clone(), canonical_value(value)?);
            }
            Ok(Value::Object(canonical))
        }
    }
}

pub fn canonical_json(payload: &Value) -> Result<Vec<u8>> {
    if !payload.is_object() {
        return Err(Error::Invalid("top-level payload must be an object"));
    }
    serde_json::to_vec(&canonical_value(payload)?).map_err(|_| Error::Invalid("serialization"))
}

pub fn parse_canonical_json(raw: &[u8]) -> Result<Value> {
    let payload: Value =
        serde_json::from_slice(raw).map_err(|_| Error::Invalid("malformed JSON"))?;
    if canonical_json(&payload)? != raw {
        return Err(Error::NonCanonical);
    }
    Ok(payload)
}

fn header(payload: &Value, kind: Kind) -> Result<()> {
    let object = payload
        .as_object()
        .ok_or(Error::Invalid("payload must be object"))?;
    if object.get("schema").and_then(Value::as_str) != Some(kind.schema())
        || object.get("schema_version").and_then(Value::as_str) != Some(VERSION)
    {
        return Err(Error::Invalid("unsupported schema version"));
    }
    Ok(())
}

/// Hash framing: domain || u16-le(schema length) || schema ||
/// u16-le(version length) || version || u32-le(canonical payload length) || payload.
pub fn hash(kind: Kind, payload: &Value) -> Result<[u8; 32]> {
    header(payload, kind)?;
    let schema = kind.schema().as_bytes();
    let version = VERSION.as_bytes();
    let body = canonical_json(payload)?;
    let mut hasher = Sha256::new();
    hasher.update(kind.domain());
    hasher.update((schema.len() as u16).to_le_bytes());
    hasher.update(schema);
    hasher.update((version.len() as u16).to_le_bytes());
    hasher.update(version);
    hasher.update((body.len() as u32).to_le_bytes());
    hasher.update(body);
    Ok(hasher.finalize().into())
}

pub fn hex(hash: [u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn resolver_definition_hash(payload: &Value) -> Result<[u8; 32]> {
    hash(Kind::Definition, payload)
}
pub fn evidence_hash(payload: &Value) -> Result<[u8; 32]> {
    hash(Kind::Evidence, payload)
}
pub fn verification_result_hash(payload: &Value) -> Result<[u8; 32]> {
    hash(Kind::Verification, payload)
}
pub fn resolution_bundle_hash(payload: &Value) -> Result<[u8; 32]> {
    hash(Kind::Bundle, payload)
}
pub fn trust_model_digest(payload: &Value) -> Result<[u8; 32]> {
    hash(Kind::TrustModel, payload)
}
pub fn adapter_digest(payload: &Value) -> Result<[u8; 32]> {
    hash(Kind::Adapter, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector() -> Value {
        serde_json::from_slice(include_bytes!("../../../resolver-v2/test-vectors/v2.json")).unwrap()
    }

    #[test]
    fn permanent_vector_matches_all_component_hashes() {
        let vector = vector();
        let bundle = &vector["bundle_payload"];
        let expected = &vector["hashes"];
        assert_eq!(
            hex(adapter_digest(&bundle["verifier"]).unwrap()),
            expected["adapter"]
        );
        assert_eq!(
            hex(trust_model_digest(&bundle["trust_model"]).unwrap()),
            expected["trust_model"]
        );
        assert_eq!(
            hex(resolver_definition_hash(&bundle["resolver_definition"]).unwrap()),
            expected["definition"]
        );
        assert_eq!(
            hex(resolution_bundle_hash(bundle).unwrap()),
            expected["bundle"]
        );
        for (index, evidence) in bundle["evidence"].as_array().unwrap().iter().enumerate() {
            assert_eq!(
                hex(evidence_hash(evidence).unwrap()),
                expected["evidence"][index]
            );
        }
        for (index, result) in bundle["verification_results"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            assert_eq!(
                hex(verification_result_hash(result).unwrap()),
                expected["verification"][index]
            );
        }
    }

    #[test]
    fn rejects_numbers_decomposed_unicode_and_noncanonical_encoding() {
        assert!(canonical_json(&serde_json::json!({"number": 1})).is_err());
        assert!(canonical_json(&serde_json::json!({"text": "Cafe\u{301}"})).is_err());
        assert_eq!(
            parse_canonical_json(br#"{ "schema":"x","schema_version":"2.0.0"}"#),
            Err(Error::NonCanonical)
        );
    }

    #[test]
    fn v2_hashes_cannot_be_interpreted_as_legacy_resolver_hashes() {
        let definition = &vector()["bundle_payload"]["resolver_definition"];
        let canonical = canonical_json(definition).unwrap();
        let legacy: [u8; 32] = Sha256::digest(canonical).into();
        assert_ne!(resolver_definition_hash(definition).unwrap(), legacy);

        let bundle = &vector()["bundle_payload"];
        let legacy_bundle: [u8; 32] = Sha256::digest(canonical_json(bundle).unwrap()).into();
        assert_ne!(resolution_bundle_hash(bundle).unwrap(), legacy_bundle);
    }

    #[test]
    fn property_hashing_is_deterministic_for_many_canonical_payloads() {
        let template = vector()["bundle_payload"]["resolver_definition"].clone();
        for seed in 0..2_048_u64 {
            let mut definition = template.clone();
            definition["source"]["seed"] = Value::String(seed.to_string());
            let first = resolver_definition_hash(&definition).unwrap();
            let second = resolver_definition_hash(&definition).unwrap();
            assert_eq!(first, second, "seed {seed}");
            let legacy: [u8; 32] = Sha256::digest(canonical_json(&definition).unwrap()).into();
            assert_ne!(first, legacy, "seed {seed}");
        }
    }
}
