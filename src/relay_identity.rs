//! Relay self-identity + signed delivery receipts (mlaify/aegis-relay#32).
//!
//! Each relay holds its own hybrid signing identity (Ed25519 + ML-DSA-65).
//! At first boot the relay generates the keypair, signs its own
//! `IdentityDocument`, and persists everything via the storage layer.
//! On subsequent boots the keypair is loaded from storage.
//!
//! The public document — including the signing keys — is exposed via
//! `/.well-known/aegis-config` so peers can discover this relay's
//! signing material and verify the receipts it returns on inbound
//! `POST /v1/envelopes`.
//!
//! Receipts ride back in the `StoreEnvelopeResponse` body. The signature
//! input is the canonical JSON of `(envelope_id, received_at,
//! receiver_relay_id)` so a peer can independently reproduce + verify
//! without trusting our hashing of the bytes.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use aegis_crypto::keygen::HybridPqKeyBundle;
use aegis_identity::{
    sign_identity_document, HybridPqPrivateKeyMaterial, ALG_ED25519, ALG_MLDSA65, ALG_MLKEM768,
    ALG_X25519, SUITE_HYBRID_PQ,
};
use aegis_proto::{IdentityDocument, IdentityId, PublicKeyRecord};

use crate::storage::RelayIdentity;

/// `did:key`-shaped DID for the freshly-generated relay identity. We
/// use the same `amp:did:key:z<random>` shape clients use so peers
/// don't need a separate parser path; the prefix is purely a signal
/// that "this is a self-managed relay key, not a user identity".
fn fresh_relay_did() -> String {
    format!(
        "amp:did:key:zRelay{}",
        uuid::Uuid::new_v4().simple()
    )
}

/// Generate a fresh hybrid signing identity for the relay. Same key
/// shape as a client identity — `aegis-crypto::HybridPqKeyBundle`
/// produces the four key materials we need (Ed25519 + ML-DSA-65 for
/// signing, X25519 + ML-KEM-768 for encryption). The relay only
/// actually uses the signing pair for receipts; keeping the encryption
/// keys around is harmless and matches the existing identity schema
/// (and lets us reuse `sign_identity_document` unchanged).
pub fn generate() -> Result<RelayIdentity, RelayIdentityError> {
    let identity_id = fresh_relay_did();
    let bundle = HybridPqKeyBundle::generate();
    let mut doc = IdentityDocument {
        version: 1,
        identity_id: IdentityId(identity_id.clone()),
        aliases: vec![],
        signing_keys: vec![
            PublicKeyRecord {
                key_id: "sig-ed25519-1".into(),
                algorithm: ALG_ED25519.into(),
                public_key_b64: B64.encode(bundle.ed25519_verifying_key_bytes),
            },
            PublicKeyRecord {
                key_id: "sig-mldsa65-1".into(),
                algorithm: ALG_MLDSA65.into(),
                public_key_b64: B64.encode(&bundle.dilithium3_public_key_bytes),
            },
        ],
        encryption_keys: vec![
            PublicKeyRecord {
                key_id: "enc-x25519-1".into(),
                algorithm: ALG_X25519.into(),
                public_key_b64: B64.encode(bundle.x25519_public_key_bytes),
            },
            PublicKeyRecord {
                key_id: "enc-mlkem768-1".into(),
                algorithm: ALG_MLKEM768.into(),
                public_key_b64: B64.encode(&bundle.kyber768_public_key_bytes),
            },
        ],
        supported_suites: vec![SUITE_HYBRID_PQ.into()],
        relay_endpoints: vec![],
        signature: None,
    };

    // Sign in-place; same path the FFI uses for client identities.
    sign_identity_document(
        &mut doc,
        &bundle.ed25519_signing_seed_bytes,
        &bundle.dilithium3_secret_key_bytes,
    )
    .map_err(|e| RelayIdentityError::Sign(format!("{e:?}")))?;

    let secrets = HybridPqPrivateKeyMaterial {
        identity_id: identity_id.clone(),
        algorithm: HybridPqPrivateKeyMaterial::algorithm_marker().to_string(),
        x25519_private_key_b64: B64.encode(bundle.x25519_private_key_bytes),
        kyber768_secret_key_b64: B64.encode(&bundle.kyber768_secret_key_bytes),
        ed25519_signing_seed_b64: B64.encode(bundle.ed25519_signing_seed_bytes),
        dilithium3_secret_key_b64: B64.encode(&bundle.dilithium3_secret_key_bytes),
    };

    let document_json =
        serde_json::to_string(&doc).map_err(|e| RelayIdentityError::Serialize(e.to_string()))?;
    let secrets_json = serde_json::to_string(&secrets)
        .map_err(|e| RelayIdentityError::Serialize(e.to_string()))?;

    Ok(RelayIdentity {
        identity_id,
        document_json,
        secrets_json,
    })
}

/// Signed delivery receipt returned by the receiving relay on every
/// successful `POST /v1/envelopes`. Sender stores this verbatim in
/// `outbound_deliveries.receipt_json` for forensic / dispute resolution
/// later. Sender-side verification ships in PR 2 of #32.
///
/// The signature covers the canonical JSON of `(envelope_id, received_at,
/// receiver_relay_id)` — peer can reconstruct that triple from the
/// receipt itself + the envelope id they pushed, then verify the
/// signature against this relay's published `signing_keys`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryReceipt {
    /// Echoes the envelope id the sender pushed. Lets the sender
    /// disambiguate concurrent receipts at audit time.
    pub envelope_id: String,
    /// RFC-3339 UTC timestamp at which this relay accepted the envelope.
    pub received_at: String,
    /// The receiving relay's identity_id (`amp:did:key:zRelay…`). Lets
    /// the sender know which relay's signing keys to verify against
    /// (peers MAY publish multiple identities at the same hostname
    /// during key rotation).
    pub receiver_relay_id: String,
    /// Hybrid signature over the canonical JSON of `ReceiptCanonical`.
    /// Format mirrors `IdentityDocument.signature`:
    /// `"ed25519:<b64>|dilithium3:<b64>"`.
    pub signature: String,
}

/// The exact bytes that the signature covers. Kept as a separate
/// struct so producers + verifiers serialize using the same Codable
/// path — equality of struct → equality of bytes → equality of
/// signature input.
#[derive(Debug, Serialize, Deserialize)]
struct ReceiptCanonical<'a> {
    envelope_id: &'a str,
    received_at: &'a str,
    receiver_relay_id: &'a str,
}

/// Sign a freshly-built receipt for `envelope_id`, `received_at`. Pulls
/// the secrets out of the persisted `HybridPqPrivateKeyMaterial` JSON.
/// Pure async-free function so it's cheap to call from the
/// hot-path of `store_envelope`.
pub fn sign_receipt(
    identity: &RelayIdentity,
    envelope_id: &str,
    received_at: &str,
) -> Result<DeliveryReceipt, RelayIdentityError> {
    use ed25519_dalek::{Signer, SigningKey};
    use ml_dsa::{
        signature::Signer as _, EncodedSignature, KeyGen, MlDsa65, Seed as MlDsaSeed,
        SigningKey as MlDsaSigningKey,
    };

    let secrets: HybridPqPrivateKeyMaterial = serde_json::from_str(&identity.secrets_json)
        .map_err(|e| RelayIdentityError::Serialize(e.to_string()))?;

    let canonical = ReceiptCanonical {
        envelope_id,
        received_at,
        receiver_relay_id: &identity.identity_id,
    };
    let canonical_bytes = serde_json::to_vec(&canonical)
        .map_err(|e| RelayIdentityError::Serialize(e.to_string()))?;

    // Ed25519 sign — same key derivation path as client identities.
    let ed_seed_bytes = B64
        .decode(&secrets.ed25519_signing_seed_b64)
        .map_err(|e| RelayIdentityError::DecodeKey(e.to_string()))?;
    let ed_seed: [u8; 32] = ed_seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RelayIdentityError::DecodeKey("ed25519 seed not 32 bytes".into()))?;
    let signing_key = SigningKey::from_bytes(&ed_seed);
    let ed_sig = signing_key.sign(&canonical_bytes);
    let ed_b64 = B64.encode(ed_sig.to_bytes());

    // ML-DSA-65 sign — `aegis_identity::sign_identity_document` shows
    // the same recipe: the persisted secret is a 32-byte seed; the
    // FIPS-204 signing key is reconstructed from it on the fly.
    let mldsa_seed_bytes = B64
        .decode(&secrets.dilithium3_secret_key_b64)
        .map_err(|e| RelayIdentityError::DecodeKey(e.to_string()))?;
    let mldsa_seed: MlDsaSeed = MlDsaSeed::try_from(mldsa_seed_bytes.as_slice())
        .map_err(|_| RelayIdentityError::DecodeKey("ml-dsa seed wrong length".into()))?;
    let mldsa_sk: MlDsaSigningKey<MlDsa65> = <MlDsa65 as KeyGen>::from_seed(&mldsa_seed);
    let mldsa_sig = mldsa_sk.sign(&canonical_bytes);
    let mldsa_sig_bytes: EncodedSignature<MlDsa65> = mldsa_sig.encode();
    let dil_b64 = B64.encode(mldsa_sig_bytes.as_slice());

    Ok(DeliveryReceipt {
        envelope_id: envelope_id.to_string(),
        received_at: received_at.to_string(),
        receiver_relay_id: identity.identity_id.clone(),
        signature: format!("ed25519:{ed_b64}|dilithium3:{dil_b64}"),
    })
}

/// Pluck just the public document out of a stored `RelayIdentity`. Used
/// by `discovery::well_known_aegis_config` to surface the relay's
/// signing keys without exposing the secret material. Returns the
/// parsed `IdentityDocument` rather than the JSON string so the
/// discovery handler can compose it into its existing response shape.
pub fn public_document(identity: &RelayIdentity) -> Result<IdentityDocument, RelayIdentityError> {
    serde_json::from_str(&identity.document_json)
        .map_err(|e| RelayIdentityError::Serialize(e.to_string()))
}

#[derive(Debug)]
pub enum RelayIdentityError {
    Sign(String),
    Serialize(String),
    DecodeKey(String),
}

impl std::fmt::Display for RelayIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sign(s) => write!(f, "failed to sign: {s}"),
            Self::Serialize(s) => write!(f, "JSON encode/decode failed: {s}"),
            Self::DecodeKey(s) => write!(f, "key decode failed: {s}"),
        }
    }
}

impl std::error::Error for RelayIdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: generate → sign a receipt → verify the signature
    /// matches the embedded canonical bytes against the same identity's
    /// public keys. End-to-end-ish smoke test that's purely in-process.
    #[test]
    fn sign_receipt_round_trip() {
        let identity = generate().expect("generate");
        let received_at = "2026-05-08T03:14:15Z";
        let envelope_id = "env-test-1";
        let receipt = sign_receipt(&identity, envelope_id, received_at).expect("sign");

        assert_eq!(receipt.envelope_id, envelope_id);
        assert_eq!(receipt.received_at, received_at);
        assert_eq!(receipt.receiver_relay_id, identity.identity_id);

        // Signature line shape — same format identity_routes expects.
        assert!(
            receipt.signature.starts_with("ed25519:"),
            "expected ed25519 prefix, got {}",
            receipt.signature
        );
        assert!(
            receipt.signature.contains("|dilithium3:"),
            "expected dilithium3 component, got {}",
            receipt.signature
        );

        // Verify the Ed25519 component end-to-end by reconstructing
        // the canonical bytes + grabbing the signing key's public from
        // the published doc.
        verify_ed25519_component(&identity, &receipt);
    }

    fn verify_ed25519_component(identity: &RelayIdentity, receipt: &DeliveryReceipt) {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let doc: IdentityDocument =
            serde_json::from_str(&identity.document_json).expect("parse doc");
        let ed_pub_b64 = doc
            .signing_keys
            .iter()
            .find(|k| k.algorithm == ALG_ED25519)
            .expect("ed25519 key in doc")
            .public_key_b64
            .clone();
        let ed_pub_bytes = B64.decode(&ed_pub_b64).expect("decode pub");
        let ed_pub: [u8; 32] = ed_pub_bytes.as_slice().try_into().expect("32 bytes");
        let vk = VerifyingKey::from_bytes(&ed_pub).expect("verifying key");

        // Pull out the ed25519:<b64> chunk from the signature line.
        let ed_part = receipt
            .signature
            .split('|')
            .find(|p| p.starts_with("ed25519:"))
            .unwrap()
            .strip_prefix("ed25519:")
            .unwrap();
        let sig_bytes = B64.decode(ed_part).expect("decode sig");
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().expect("sig 64 bytes");
        let sig = Signature::from_bytes(&sig);

        // Recompute the canonical bytes the signer used.
        let canonical = ReceiptCanonical {
            envelope_id: &receipt.envelope_id,
            received_at: &receipt.received_at,
            receiver_relay_id: &receipt.receiver_relay_id,
        };
        let canonical_bytes = serde_json::to_vec(&canonical).unwrap();

        vk.verify(&canonical_bytes, &sig).expect("ed25519 verifies");
    }

    #[test]
    fn generated_identity_has_published_signing_keys() {
        let identity = generate().expect("generate");
        let doc = public_document(&identity).expect("parse public doc");
        assert_eq!(doc.identity_id.0, identity.identity_id);

        let algos: Vec<_> = doc.signing_keys.iter().map(|k| k.algorithm.as_str()).collect();
        assert!(algos.contains(&ALG_ED25519));
        assert!(algos.contains(&ALG_MLDSA65));

        // Should be self-signed already (matches identity_routes' expectation).
        assert!(
            doc.signature.is_some(),
            "freshly-generated identity should be signed in-place"
        );
    }

    #[test]
    fn fresh_did_starts_with_amp_did_key_zrelay_prefix() {
        let id = fresh_relay_did();
        assert!(id.starts_with("amp:did:key:zRelay"), "{id}");
        // 32 hex chars from UUID's simple form gives a stable length.
        assert_eq!(id.len(), "amp:did:key:zRelay".len() + 32);
    }
}
