//! Cryptographic primitives for Phi: Ed25519 keys and signatures.
//!
//! This is the first slice of the `phi-crypto` crate from
//! docs/ARCHITECTURE.md §2 (Phase 1b in docs/ROADMAP.md): real signature
//! verification for account auth policies and validator votes. VRF sortition
//! and threshold BLS land here in later phases. Signature algorithms are an
//! account-level choice in the protocol (docs/SPECIFICATION.md §6), so these
//! newtypes deliberately hide the backing library from the rest of the stack.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LEN]);

/// A detached Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

/// An Ed25519 signing keypair.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Derive a keypair from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Deterministic keypair from a human label (test/simulation helper —
    /// real wallets derive seeds from passkeys or OS keystores).
    pub fn from_label(label: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phi:keyseed");
        hasher.update(label.as_bytes());
        Self::from_seed(*hasher.finalize().as_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.signing.sign(message).to_bytes())
    }
}

impl PublicKey {
    /// Verify a signature over `message`. Uses strict verification, which
    /// rejects malleable encodings and low-order public keys — consensus
    /// objects must have exactly one valid byte representation.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        key.verify_strict(message, &sig).is_ok()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pk:")?;
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sig:")?;
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Keypair::from_label("alice");
        let sig = kp.sign(b"hello phi");
        assert!(kp.public().verify(b"hello phi", &sig));
    }

    #[test]
    fn wrong_key_rejected() {
        let alice = Keypair::from_label("alice");
        let mallory = Keypair::from_label("mallory");
        let sig = mallory.sign(b"transfer all funds");
        assert!(!alice.public().verify(b"transfer all funds", &sig));
    }

    #[test]
    fn tampered_message_rejected() {
        let kp = Keypair::from_label("alice");
        let sig = kp.sign(b"amount=10");
        assert!(!kp.public().verify(b"amount=10000", &sig));
    }

    #[test]
    fn label_derivation_is_deterministic() {
        let a = Keypair::from_label("validator-0");
        let b = Keypair::from_label("validator-0");
        let c = Keypair::from_label("validator-1");
        assert_eq!(a.public(), b.public());
        assert_ne!(a.public(), c.public());
    }
}
