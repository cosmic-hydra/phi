//! Binary Merkle tree over 32-byte leaves, with inclusion proofs.
//!
//! Two hardening measures over a naive construction:
//! - Leaves and interior nodes are hashed under different domain tags, so an
//!   interior node can never be reinterpreted as a leaf (second-preimage
//!   shaping attacks).
//! - An odd node at the end of a level is *promoted* unchanged to the next
//!   level instead of being paired with a copy of itself. Duplicating the
//!   last leaf (Bitcoin's CVE-2012-2459) makes `[A, B, C]` and `[A, B, C, C]`
//!   commit to the same root; promotion keeps every distinct leaf list at a
//!   distinct root.

use crate::hash::Hash;

fn leaf_hash(leaf: &Hash) -> Hash {
    Hash::of_tagged(b"nex:merkle:leaf", &[leaf.as_bytes()])
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Hash::of_tagged(b"nex:merkle:node", &[left.as_bytes(), right.as_bytes()])
}

/// Root committing to an empty leaf list (distinct from any real root).
pub fn empty_root() -> Hash {
    Hash::of_tagged(b"nex:merkle:empty", &[])
}

/// Merkle root over `leaves`.
pub fn root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<Hash> = leaves.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => node_hash(left, right),
                [promoted] => *promoted,
                _ => unreachable!("chunks(2) yields 1- or 2-element slices"),
            })
            .collect();
    }
    level[0]
}

/// Inclusion proof for one leaf: the sibling hashes from leaf level to root.
/// Levels where the node is promoted (odd tail) contribute no sibling, so the
/// verifier needs the original `leaf_count` to replay the tree shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub siblings: Vec<Hash>,
}

/// Build the inclusion proof for `leaves[index]`.
pub fn prove(leaves: &[Hash], index: usize) -> Option<MerkleProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut siblings = Vec::new();
    let mut level: Vec<Hash> = leaves.iter().map(leaf_hash).collect();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = idx ^ 1;
        if sibling < level.len() {
            siblings.push(level[sibling]);
        }
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => node_hash(left, right),
                [promoted] => *promoted,
                _ => unreachable!(),
            })
            .collect();
        idx /= 2;
    }
    Some(MerkleProof { siblings })
}

/// Verify that `leaf` sits at `index` in a tree of `leaf_count` leaves with
/// the given `root`.
pub fn verify(
    expected_root: &Hash,
    leaf: &Hash,
    index: usize,
    leaf_count: usize,
    proof: &MerkleProof,
) -> bool {
    if leaf_count == 0 || index >= leaf_count {
        return false;
    }
    let mut current = leaf_hash(leaf);
    let mut siblings = proof.siblings.iter();
    let mut idx = index;
    let mut width = leaf_count;
    while width > 1 {
        if idx ^ 1 < width {
            let Some(sibling) = siblings.next() else {
                return false;
            };
            current = if idx.is_multiple_of(2) {
                node_hash(&current, sibling)
            } else {
                node_hash(sibling, &current)
            };
        }
        idx /= 2;
        width = width.div_ceil(2);
    }
    siblings.next().is_none() && current == *expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| Hash::of(&[i as u8])).collect()
    }

    #[test]
    fn empty_and_single_leaf_roots_are_distinct() {
        let single = leaves(1);
        assert_ne!(root(&[]), root(&single));
        assert_ne!(root(&single), single[0], "leaf must be domain-tagged");
    }

    #[test]
    fn duplicating_the_last_leaf_changes_the_root() {
        // Regression for the CVE-2012-2459-style mutation the previous
        // duplicate-last-leaf construction allowed.
        let abc = leaves(3);
        let mut abcc = abc.clone();
        abcc.push(abc[2]);
        assert_ne!(root(&abc), root(&abcc));
    }

    #[test]
    fn proofs_verify_for_every_index_and_size() {
        for n in 1..=9 {
            let ls = leaves(n);
            let r = root(&ls);
            for i in 0..n {
                let proof = prove(&ls, i).unwrap();
                assert!(verify(&r, &ls[i], i, n, &proof), "n={n} i={i}");
                // Wrong leaf, wrong index, truncated proof all fail.
                assert!(!verify(&r, &Hash::of(b"bogus"), i, n, &proof));
                assert!(!verify(&r, &ls[i], (i + 1) % n, n, &proof) || n == 1);
                if !proof.siblings.is_empty() {
                    let short = MerkleProof {
                        siblings: proof.siblings[..proof.siblings.len() - 1].to_vec(),
                    };
                    assert!(!verify(&r, &ls[i], i, n, &short));
                }
            }
        }
    }

    #[test]
    fn proof_with_extra_siblings_rejected() {
        let ls = leaves(4);
        let r = root(&ls);
        let mut proof = prove(&ls, 0).unwrap();
        proof.siblings.push(Hash::of(b"extra"));
        assert!(!verify(&r, &ls[0], 0, 4, &proof));
    }
}
