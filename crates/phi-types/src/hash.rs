//! 32-byte BLAKE3 hash newtype used throughout the protocol.

use std::fmt;

/// A 32-byte content hash (BLAKE3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);

    /// Hash arbitrary bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Hash(*blake3::hash(bytes).as_bytes())
    }

    /// Domain-separated, length-prefixed hash of structured input.
    ///
    /// Every part is prefixed with its u32-LE length, so two different part
    /// lists can never produce the same byte stream — this is what all
    /// consensus-critical hashes (transaction ids, headers, Merkle/SMT nodes)
    /// must use. Plain concatenation is only safe for fixed-width inputs.
    pub fn of_tagged(tag: &[u8], parts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(tag.len() as u32).to_le_bytes());
        hasher.update(tag);
        for p in parts {
            hasher.update(&(p.len() as u32).to_le_bytes());
            hasher.update(p);
        }
        Hash(*hasher.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_hash_is_not_ambiguous_across_part_boundaries() {
        // Same concatenated bytes, different part split -> different hash.
        let a = Hash::of_tagged(b"t", &[b"ab", b"c"]);
        let b = Hash::of_tagged(b"t", &[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn tagged_hash_separates_domains() {
        assert_ne!(
            Hash::of_tagged(b"domain-a", &[b"payload"]),
            Hash::of_tagged(b"domain-b", &[b"payload"])
        );
    }
}
