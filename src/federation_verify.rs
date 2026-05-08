//! Sender-side receipt verification + trusted-peer allowlist for
//! federation (mlaify/aegis-relay#32 part 2).
//!
//! After a successful federation push, the receiving relay returns a
//! `DeliveryReceipt` signed with its hybrid keypair (Ed25519 +
//! ML-DSA-65). This module:
//!
//!   1. Fetches the peer's `/.well-known/aegis-config` (cached with
//!      a TTL — peers' signing keys don't rotate often, but rotation
//!      should propagate within minutes, not days).
//!   2. Verifies BOTH signature components against the peer's
//!      published `signing_keys`. Hybrid means hybrid: a peer that
//!      drops one component is treated as misbehaving (mark expired).
//!   3. Optionally enforces a trusted-peer allowlist
//!      (`AEGIS_FEDERATION_TRUSTED_PEERS`) — when set, deliveries to
//!      a peer whose published `relay_id` isn't in the list fail
//!      pre-flight without ever leaving the host.
//!
//! Notes on threat model:
//!   - The receipt's `receiver_relay_id` is the cryptographic anchor.
//!     We never trust the URL alone — a malicious tunnel could route
//!     to a different relay than DNS implies, but only the legitimate
//!     peer's signing keys can produce a valid receipt for the ID
//!     in the trusted list.
//!   - Cache TTL is 5 minutes by default. A compromised peer that
//!     rotates keys to lock out the legitimate operator would still
//!     have a 5-minute window where stale keys verify; for stronger
//!     guarantees operators can shrink the TTL.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use aegis_identity::{ALG_ED25519, ALG_MLDSA65};
use aegis_proto::{IdentityDocument, PublicKeyRecord};

use crate::relay_identity::DeliveryReceipt;

/// In-memory peer-discovery cache. Keyed on the peer's federation URL
/// (the `target_url` from `outbound_deliveries`) so we don't re-fetch
/// `/.well-known/aegis-config` for every delivery to a known peer.
///
/// A `Mutex<HashMap>` is sufficient — the federation worker is
/// single-threaded by construction (one polling loop), and the
/// occasional contention from a second background task is cheap.
pub struct DiscoveryCache {
    inner: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

struct CacheEntry {
    document: IdentityDocument,
    fetched_at: Instant,
}

impl DiscoveryCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Default cache: 5-minute TTL. Tuned for a sweet spot between
    /// re-fetching unnecessarily on a busy relay (a 30s interval would
    /// thrash) and locking in stale keys for too long after a peer
    /// rotates. Operators can override via env var if they want.
    pub fn default_ttl() -> Self {
        Self::new(Duration::from_secs(300))
    }

    /// Fetch the cached document if it's still fresh, else `None`.
    /// Returning `None` means "go fetch from the network".
    pub fn get(&self, target_url: &str) -> Option<IdentityDocument> {
        let cache = self.inner.lock().unwrap();
        let entry = cache.get(target_url)?;
        if entry.fetched_at.elapsed() < self.ttl {
            Some(entry.document.clone())
        } else {
            None
        }
    }

    /// Insert / refresh the cache for a target URL.
    pub fn put(&self, target_url: String, document: IdentityDocument) {
        let mut cache = self.inner.lock().unwrap();
        cache.insert(
            target_url,
            CacheEntry {
                document,
                fetched_at: Instant::now(),
            },
        );
    }

    /// Drop the cached entry for a target URL — used after a verify
    /// failure so the next attempt re-fetches and picks up a key
    /// rotation that landed since we last looked.
    pub fn invalidate(&self, target_url: &str) {
        let mut cache = self.inner.lock().unwrap();
        cache.remove(target_url);
    }
}

/// Fetch a peer's discovery doc, going through the cache. Single-flight
/// behavior is delegated to the caller — the federation worker is
/// inherently serialized so we don't bother with `Notify` here.
pub async fn fetch_peer_identity(
    cache: &DiscoveryCache,
    client: &reqwest::Client,
    target_url: &str,
) -> Result<IdentityDocument, FederationVerifyError> {
    if let Some(cached) = cache.get(target_url) {
        return Ok(cached);
    }

    let url = format!(
        "{}/.well-known/aegis-config",
        target_url.trim_end_matches('/')
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| FederationVerifyError::DiscoveryFetch(e.to_string()))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Peer doesn't expose discovery — could be running an older
        // relay that doesn't ship #32, OR running the current relay
        // without any claimed domains (the discovery handler 404s in
        // open-relay mode). Either way the sender can't fetch a
        // signing identity, so we report PeerHasNoIdentity. The
        // caller decides whether to refuse delivery (allowlist on)
        // or proceed without verification (allowlist off).
        return Err(FederationVerifyError::PeerHasNoIdentity);
    }
    if !resp.status().is_success() {
        return Err(FederationVerifyError::DiscoveryFetch(format!(
            "{} → HTTP {}",
            url,
            resp.status()
        )));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FederationVerifyError::DiscoveryFetch(e.to_string()))?;

    // The relay_identity field is optional — older peers that haven't
    // shipped #32 part 1 won't include one. Treat that as "can't
    // verify receipts" rather than "verification failed".
    let doc_value = body
        .get("relay_identity")
        .and_then(|v| if v.is_null() { None } else { Some(v.clone()) })
        .ok_or(FederationVerifyError::PeerHasNoIdentity)?;
    let document: IdentityDocument = serde_json::from_value(doc_value)
        .map_err(|e| FederationVerifyError::DiscoveryFetch(e.to_string()))?;

    cache.put(target_url.to_string(), document.clone());
    Ok(document)
}

/// Verify a `DeliveryReceipt` against the peer's published identity.
/// Both Ed25519 and ML-DSA-65 signatures must validate — hybrid PQ
/// means we don't accept a receipt with one half missing or wrong.
///
/// Returns `Ok(())` only when:
///   - `receipt.receiver_relay_id` == `peer_doc.identity_id`
///   - the canonical bytes can be reconstructed from the receipt
///   - both signature components verify against the corresponding key
pub fn verify_receipt(
    receipt: &DeliveryReceipt,
    peer_doc: &IdentityDocument,
) -> Result<(), FederationVerifyError> {
    use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};
    use ml_dsa::{
        signature::Verifier as MlDsaVerifier, EncodedSignature, EncodedVerifyingKey, MlDsa65,
        Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
    };

    // 1. Cross-check the receipt's identity claim against the doc.
    if receipt.receiver_relay_id != peer_doc.identity_id.0 {
        return Err(FederationVerifyError::IdentityMismatch {
            expected: peer_doc.identity_id.0.clone(),
            got: receipt.receiver_relay_id.clone(),
        });
    }

    // 2. Reconstruct the canonical bytes the signer covered. Same shape
    //    as `relay_identity::ReceiptCanonical` — we serialize the same
    //    keys in the same order so byte equality holds.
    #[derive(serde::Serialize)]
    struct Canonical<'a> {
        envelope_id: &'a str,
        received_at: &'a str,
        receiver_relay_id: &'a str,
    }
    let canonical_bytes = serde_json::to_vec(&Canonical {
        envelope_id: &receipt.envelope_id,
        received_at: &receipt.received_at,
        receiver_relay_id: &receipt.receiver_relay_id,
    })
    .map_err(|e| FederationVerifyError::CanonicalEncode(e.to_string()))?;

    // 3. Split the signature line into its two components.
    let (ed_b64, ml_b64) = parse_signature_line(&receipt.signature)?;

    // 4. Find the peer's published keys.
    let ed_pub = find_signing_key(peer_doc, ALG_ED25519)?;
    let ml_pub = find_signing_key(peer_doc, ALG_MLDSA65)?;

    // 5. Verify Ed25519.
    let ed_pub_bytes = B64
        .decode(&ed_pub.public_key_b64)
        .map_err(|e| FederationVerifyError::DecodeKey(e.to_string()))?;
    let ed_pub_array: [u8; 32] = ed_pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| FederationVerifyError::DecodeKey("ed25519 pubkey not 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&ed_pub_array)
        .map_err(|e| FederationVerifyError::DecodeKey(e.to_string()))?;
    let ed_sig_bytes = B64
        .decode(ed_b64)
        .map_err(|e| FederationVerifyError::DecodeSignature(e.to_string()))?;
    let ed_sig_array: [u8; 64] = ed_sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| FederationVerifyError::DecodeSignature("ed25519 sig not 64 bytes".into()))?;
    let ed_sig = EdSignature::from_bytes(&ed_sig_array);
    vk.verify(&canonical_bytes, &ed_sig)
        .map_err(|_| FederationVerifyError::VerifyFailed("ed25519 signature did not verify".into()))?;

    // 6. Verify ML-DSA-65 (FIPS 204). The published key is the
    //    EncodedVerifyingKey form; reconstruct + verify.
    let ml_pub_bytes = B64
        .decode(&ml_pub.public_key_b64)
        .map_err(|e| FederationVerifyError::DecodeKey(e.to_string()))?;
    let ml_vk_encoded = EncodedVerifyingKey::<MlDsa65>::try_from(ml_pub_bytes.as_slice())
        .map_err(|_| FederationVerifyError::DecodeKey("ml-dsa pubkey wrong length".into()))?;
    let ml_vk = MlDsaVerifyingKey::<MlDsa65>::decode(&ml_vk_encoded);
    let ml_sig_bytes = B64
        .decode(ml_b64)
        .map_err(|e| FederationVerifyError::DecodeSignature(e.to_string()))?;
    let ml_sig_encoded = EncodedSignature::<MlDsa65>::try_from(ml_sig_bytes.as_slice())
        .map_err(|_| FederationVerifyError::DecodeSignature("ml-dsa sig wrong length".into()))?;
    let ml_sig = MlDsaSignature::<MlDsa65>::decode(&ml_sig_encoded)
        .ok_or_else(|| FederationVerifyError::DecodeSignature("ml-dsa sig decode failed".into()))?;
    ml_vk
        .verify(&canonical_bytes, &ml_sig)
        .map_err(|_| FederationVerifyError::VerifyFailed("ml-dsa signature did not verify".into()))?;

    Ok(())
}

fn parse_signature_line(s: &str) -> Result<(&str, &str), FederationVerifyError> {
    // Format: "ed25519:<b64>|dilithium3:<b64>". Mirrors how
    // identity_routes packs hybrid sigs in IdentityDocument.signature.
    let mut ed = None;
    let mut ml = None;
    for part in s.split('|') {
        if let Some(rest) = part.strip_prefix("ed25519:") {
            ed = Some(rest);
        } else if let Some(rest) = part.strip_prefix("dilithium3:") {
            ml = Some(rest);
        }
    }
    match (ed, ml) {
        (Some(e), Some(m)) => Ok((e, m)),
        _ => Err(FederationVerifyError::SignatureFormat(format!(
            "expected `ed25519:<b64>|dilithium3:<b64>`, got {s:?}"
        ))),
    }
}

fn find_signing_key<'a>(
    doc: &'a IdentityDocument,
    algorithm: &str,
) -> Result<&'a PublicKeyRecord, FederationVerifyError> {
    doc.signing_keys
        .iter()
        .find(|k| k.algorithm == algorithm)
        .ok_or_else(|| {
            FederationVerifyError::PeerMissingKey(format!(
                "peer {} has no {} signing key",
                doc.identity_id.0, algorithm
            ))
        })
}

/// Resolve the trusted-peer allowlist from `AEGIS_FEDERATION_TRUSTED_PEERS`.
/// Empty / unset → `None` (open federation, current default behavior).
/// Set → comma-separated list of identity_ids; deliveries to peers
/// outside the list fail pre-flight.
pub fn trusted_peers_from_env() -> Option<Vec<String>> {
    parse_trusted_peers(std::env::var("AEGIS_FEDERATION_TRUSTED_PEERS").ok().as_deref())
}

/// Pure-function backing for `trusted_peers_from_env`. Pulls the comma-
/// separated form into a Vec, trims whitespace, and skips empty entries
/// so a stray trailing comma doesn't introduce a fake "" peer.
pub fn parse_trusted_peers(raw: Option<&str>) -> Option<Vec<String>> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    let entries: Vec<String> = s
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// True iff `peer_id` is allowed to receive federated traffic given an
/// optional allowlist. Open federation (allowlist `None`) trusts
/// everyone; a configured allowlist gates membership strictly.
pub fn is_peer_trusted(allowlist: Option<&[String]>, peer_id: &str) -> bool {
    match allowlist {
        None => true,
        Some(list) => list.iter().any(|s| s == peer_id),
    }
}

/// Errors surfaced by the receipt-verification path. `is_peer_trusted`
/// returns a bool rather than emitting `PeerNotTrusted` because the
/// federation worker logs the refusal directly and skips the verify
/// path entirely; the variant is preserved here for symmetry + so the
/// admin endpoint can attach a structured reason if it ever needs to.
#[derive(Debug)]
#[allow(dead_code)] // PeerNotTrusted unused now; reserved for future API exposure
pub enum FederationVerifyError {
    DiscoveryFetch(String),
    PeerHasNoIdentity,
    PeerNotTrusted { peer_id: String },
    IdentityMismatch { expected: String, got: String },
    PeerMissingKey(String),
    SignatureFormat(String),
    DecodeKey(String),
    DecodeSignature(String),
    CanonicalEncode(String),
    VerifyFailed(String),
}

impl std::fmt::Display for FederationVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DiscoveryFetch(s) => write!(f, "discovery fetch failed: {s}"),
            Self::PeerHasNoIdentity => write!(
                f,
                "peer's discovery doc has no relay_identity (older relay; receipt unverifiable)"
            ),
            Self::PeerNotTrusted { peer_id } => {
                write!(f, "peer {peer_id} is not in AEGIS_FEDERATION_TRUSTED_PEERS")
            }
            Self::IdentityMismatch { expected, got } => write!(
                f,
                "receipt claims receiver_relay_id={got} but peer published identity_id={expected}"
            ),
            Self::PeerMissingKey(s) => write!(f, "peer doc missing key: {s}"),
            Self::SignatureFormat(s) => write!(f, "malformed signature line: {s}"),
            Self::DecodeKey(s) => write!(f, "decode key: {s}"),
            Self::DecodeSignature(s) => write!(f, "decode signature: {s}"),
            Self::CanonicalEncode(s) => write!(f, "canonical encode: {s}"),
            Self::VerifyFailed(s) => write!(f, "verify failed: {s}"),
        }
    }
}

impl std::error::Error for FederationVerifyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_identity::{generate, sign_receipt};

    // --- Trusted-peer allowlist ----------------------------------------

    #[test]
    fn parse_trusted_peers_accepts_csv_with_whitespace() {
        let parsed = parse_trusted_peers(Some(
            " amp:did:key:zRelayA , amp:did:key:zRelayB ,, amp:did:key:zRelayC ",
        ));
        assert_eq!(
            parsed.unwrap(),
            vec![
                "amp:did:key:zRelayA".to_string(),
                "amp:did:key:zRelayB".to_string(),
                "amp:did:key:zRelayC".to_string(),
            ]
        );
    }

    #[test]
    fn parse_trusted_peers_treats_empty_as_unset() {
        // An empty env var is identical to no env var — open
        // federation, NOT "no peers allowed".
        assert!(parse_trusted_peers(None).is_none());
        assert!(parse_trusted_peers(Some("")).is_none());
        assert!(parse_trusted_peers(Some("   ")).is_none());
        assert!(parse_trusted_peers(Some(",,")).is_none());
    }

    #[test]
    fn is_peer_trusted_open_when_allowlist_unset() {
        assert!(is_peer_trusted(None, "amp:did:key:zAnyone"));
    }

    #[test]
    fn is_peer_trusted_strict_when_allowlist_set() {
        let list = vec!["amp:did:key:zAllowed".to_string()];
        assert!(is_peer_trusted(Some(&list), "amp:did:key:zAllowed"));
        assert!(!is_peer_trusted(Some(&list), "amp:did:key:zNotInList"));
        assert!(!is_peer_trusted(Some(&list), ""));
    }

    // --- Receipt verification ------------------------------------------

    #[test]
    fn verify_receipt_accepts_legitimate_receipt() {
        // Generate a real identity, sign a real receipt, verify
        // against the same identity's public document. The signing
        // and verify paths are independent code, so this is a real
        // end-to-end smoke test.
        let identity = generate().expect("generate");
        let receipt = sign_receipt(&identity, "env-vfy-1", "2026-05-08T03:14:15Z").unwrap();
        let doc = crate::relay_identity::public_document(&identity).unwrap();
        verify_receipt(&receipt, &doc).expect("legitimate receipt should verify");
    }

    #[test]
    fn verify_receipt_rejects_identity_mismatch() {
        // Receipt claims a different receiver_relay_id than the doc.
        // Could indicate a peer running multiple identities or an
        // attacker; either way, refuse.
        let identity = generate().expect("generate");
        let mut receipt = sign_receipt(&identity, "env-1", "2026-05-08T03:14:15Z").unwrap();
        receipt.receiver_relay_id = "amp:did:key:zSomethingElse".to_string();
        let doc = crate::relay_identity::public_document(&identity).unwrap();
        let err = verify_receipt(&receipt, &doc).expect_err("should fail");
        assert!(matches!(err, FederationVerifyError::IdentityMismatch { .. }));
    }

    #[test]
    fn verify_receipt_rejects_tampered_signature() {
        // Flip a bit in the signature; both halves should reject.
        let identity = generate().expect("generate");
        let receipt = sign_receipt(&identity, "env-1", "2026-05-08T03:14:15Z").unwrap();
        let doc = crate::relay_identity::public_document(&identity).unwrap();

        // Mutate the ed25519 component by truncating one b64 char.
        let mut tampered = receipt.clone();
        tampered.signature = receipt.signature.replace(":", ":X"); // corrupts both halves
        let err = verify_receipt(&tampered, &doc).expect_err("should fail");
        // Either format error or verify failure is acceptable — both
        // are correct rejections of a malformed/forged receipt.
        assert!(matches!(
            err,
            FederationVerifyError::DecodeSignature(_)
                | FederationVerifyError::SignatureFormat(_)
                | FederationVerifyError::VerifyFailed(_)
        ));
    }

    #[test]
    fn verify_receipt_rejects_signature_against_wrong_keys() {
        // Sign with identity A, verify against identity B. Crypto-
        // level rejection — the canonical bytes are valid, the
        // signature is valid for A's keys, but B's keys won't accept.
        let identity_a = generate().expect("generate A");
        let identity_b = generate().expect("generate B");
        let mut receipt = sign_receipt(&identity_a, "env-x", "2026-05-08T03:14:15Z").unwrap();
        // Force receiver_relay_id to match B so we get past the
        // identity-mismatch check and exercise the signature path.
        receipt.receiver_relay_id = identity_b.identity_id.clone();
        let doc_b = crate::relay_identity::public_document(&identity_b).unwrap();
        let err = verify_receipt(&receipt, &doc_b).expect_err("cross-identity should fail");
        assert!(matches!(err, FederationVerifyError::VerifyFailed(_)));
    }

    #[test]
    fn parse_signature_line_round_trips() {
        let parsed = parse_signature_line("ed25519:abc|dilithium3:def").unwrap();
        assert_eq!(parsed, ("abc", "def"));
    }

    #[test]
    fn parse_signature_line_rejects_missing_components() {
        assert!(parse_signature_line("ed25519:abc").is_err());
        assert!(parse_signature_line("dilithium3:abc").is_err());
        assert!(parse_signature_line("garbage").is_err());
    }

    // --- Discovery cache -----------------------------------------------

    #[test]
    fn discovery_cache_returns_some_within_ttl() {
        let cache = DiscoveryCache::new(Duration::from_secs(60));
        let identity = generate().unwrap();
        let doc = crate::relay_identity::public_document(&identity).unwrap();
        cache.put("https://peer.example".into(), doc.clone());
        let got = cache.get("https://peer.example").expect("cached");
        assert_eq!(got.identity_id.0, doc.identity_id.0);
    }

    #[test]
    fn discovery_cache_returns_none_after_ttl() {
        let cache = DiscoveryCache::new(Duration::from_millis(1));
        let identity = generate().unwrap();
        let doc = crate::relay_identity::public_document(&identity).unwrap();
        cache.put("https://peer.example".into(), doc);
        // Block briefly so the entry definitely ages out.
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get("https://peer.example").is_none());
    }

    #[test]
    fn discovery_cache_invalidate_removes_entry() {
        let cache = DiscoveryCache::new(Duration::from_secs(60));
        let identity = generate().unwrap();
        let doc = crate::relay_identity::public_document(&identity).unwrap();
        cache.put("https://peer.example".into(), doc);
        cache.invalidate("https://peer.example");
        assert!(cache.get("https://peer.example").is_none());
    }
}
