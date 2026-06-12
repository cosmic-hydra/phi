//! Sparse Merkle Tree over 32-byte keys (docs/SPECIFICATION.md §5).
//!
//! Gives the state commitment compact *inclusion and exclusion* proofs —
//! light clients can verify both "this account has balance X" and "this
//! account does not exist" against a block's state root. The tree is the
//! full 256-level binary tree over the key bit-space; empty subtrees hash to
//! precomputed defaults so only populated paths cost anything.
//!
//! Proofs are uncompressed (256 siblings ≈ 8 KiB); production compresses
//! runs of default hashes with a bitmap. Roots are recomputed from the leaf
//! map on demand (O(n·256) hashing) — the versioned, incrementally-updated
//! store replaces this without changing the interface.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use nex_types::Hash;

/// Tree depth: one level per key bit.
pub const DEPTH: usize = 256;

pub type Key = [u8; 32];

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Hash::of_tagged(b"nex:smt:node", &[left.as_bytes(), right.as_bytes()])
}

fn leaf_hash(key: &Key, value_hash: &Hash) -> Hash {
    Hash::of_tagged(b"nex:smt:leaf", &[key, value_hash.as_bytes()])
}

/// `empty(d)` is the hash of an empty subtree whose root sits at depth `d`.
fn empty(depth: usize) -> Hash {
    static EMPTY: OnceLock<Vec<Hash>> = OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut hashes = vec![Hash::ZERO; DEPTH + 1];
        hashes[DEPTH] = Hash::of_tagged(b"nex:smt:empty", &[]);
        for d in (0..DEPTH).rev() {
            hashes[d] = node_hash(&hashes[d + 1], &hashes[d + 1]);
        }
        hashes
    })[depth]
}

/// Bit `depth` of `key`, MSB-first — so bit order matches the lexicographic
/// order of `BTreeMap` keys, letting subtrees split with `partition_point`.
fn bit(key: &Key, depth: usize) -> u8 {
    (key[depth / 8] >> (7 - depth % 8)) & 1
}

/// Root of the tree containing `entries` (key → value hash).
pub fn root(entries: &BTreeMap<Key, Hash>) -> Hash {
    let flat: Vec<(&Key, &Hash)> = entries.iter().collect();
    subtree_root(&flat, 0)
}

fn subtree_root(entries: &[(&Key, &Hash)], depth: usize) -> Hash {
    if entries.is_empty() {
        return empty(depth);
    }
    if depth == DEPTH {
        debug_assert_eq!(entries.len(), 1, "duplicate key in SMT");
        return leaf_hash(entries[0].0, entries[0].1);
    }
    let split = entries.partition_point(|(key, _)| bit(key, depth) == 0);
    node_hash(
        &subtree_root(&entries[..split], depth + 1),
        &subtree_root(&entries[split..], depth + 1),
    )
}

/// Merkle path for one key: the sibling root at every depth, top first.
/// The same structure proves inclusion (key present with a value) and
/// exclusion (key's path ends in the empty leaf).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtProof {
    pub siblings: Vec<Hash>,
}

/// Build the (in|ex)clusion proof for `key`.
pub fn prove(entries: &BTreeMap<Key, Hash>, key: &Key) -> SmtProof {
    let flat: Vec<(&Key, &Hash)> = entries.iter().collect();
    // Walk down the key's path narrowing a borrowed window — no per-level
    // copies of the entry list.
    let mut slice: &[(&Key, &Hash)] = &flat;
    let mut siblings = Vec::with_capacity(DEPTH);
    for depth in 0..DEPTH {
        let split = slice.partition_point(|(k, _)| bit(k, depth) == 0);
        let (chosen, sibling) = if bit(key, depth) == 0 {
            (&slice[..split], &slice[split..])
        } else {
            (&slice[split..], &slice[..split])
        };
        siblings.push(subtree_root(sibling, depth + 1));
        slice = chosen;
    }
    SmtProof { siblings }
}

/// Verify a proof against `expected_root`. `value_hash` is `Some` for an
/// inclusion claim and `None` for an exclusion claim.
pub fn verify(
    expected_root: &Hash,
    key: &Key,
    value_hash: Option<&Hash>,
    proof: &SmtProof,
) -> bool {
    if proof.siblings.len() != DEPTH {
        return false;
    }
    let mut current = match value_hash {
        Some(v) => leaf_hash(key, v),
        None => empty(DEPTH),
    };
    for depth in (0..DEPTH).rev() {
        let sibling = &proof.siblings[depth];
        current = if bit(key, depth) == 0 {
            node_hash(&current, sibling)
        } else {
            node_hash(sibling, &current)
        };
    }
    current == *expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(label: &str) -> Key {
        *Hash::of(label.as_bytes()).as_bytes()
    }

    fn value(label: &str) -> Hash {
        Hash::of(label.as_bytes())
    }

    fn sample() -> BTreeMap<Key, Hash> {
        ["alice", "bob", "carol", "dave", "erin"]
            .iter()
            .map(|l| (key(l), value(&format!("{l}-state"))))
            .collect()
    }

    #[test]
    fn root_is_deterministic_and_insertion_order_independent() {
        let a = sample();
        let mut b = BTreeMap::new();
        for (k, v) in a.iter().rev() {
            b.insert(*k, *v);
        }
        assert_eq!(root(&a), root(&b));
        assert_ne!(root(&a), root(&BTreeMap::new()));
    }

    #[test]
    fn root_changes_when_a_value_changes() {
        let mut entries = sample();
        let before = root(&entries);
        entries.insert(key("alice"), value("alice-modified"));
        assert_ne!(before, root(&entries));
    }

    #[test]
    fn inclusion_proofs_verify() {
        let entries = sample();
        let r = root(&entries);
        for (k, v) in &entries {
            let proof = prove(&entries, k);
            assert!(verify(&r, k, Some(v), &proof));
            // Same proof with the wrong value or as an exclusion fails.
            assert!(!verify(&r, k, Some(&value("wrong")), &proof));
            assert!(!verify(&r, k, None, &proof));
        }
    }

    #[test]
    fn exclusion_proofs_verify() {
        let entries = sample();
        let r = root(&entries);
        let absent = key("mallory");
        let proof = prove(&entries, &absent);
        assert!(verify(&r, &absent, None, &proof));
        assert!(!verify(&r, &absent, Some(&value("forged")), &proof));
    }

    #[test]
    fn exclusion_stops_verifying_after_insert() {
        let mut entries = sample();
        let k = key("mallory");
        let old_root = root(&entries);
        let old_proof = prove(&entries, &k);
        assert!(verify(&old_root, &k, None, &old_proof));

        entries.insert(k, value("mallory-state"));
        let new_root = root(&entries);
        assert!(!verify(&new_root, &k, None, &old_proof));
        let new_proof = prove(&entries, &k);
        assert!(verify(
            &new_root,
            &k,
            Some(&value("mallory-state")),
            &new_proof
        ));
    }

    #[test]
    fn truncated_proof_rejected() {
        let entries = sample();
        let r = root(&entries);
        let k = key("alice");
        let mut proof = prove(&entries, &k);
        proof.siblings.pop();
        assert!(!verify(&r, &k, Some(&value("alice-state")), &proof));
    }
}
