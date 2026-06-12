//! Core protocol types for Phi: hashes, accounts, transactions, blocks.
//!
//! Design notes (see docs/SPECIFICATION.md):
//! - Every account is a smart account (native account abstraction). Account
//!   ids commit to the controlling `AuthPolicy`; accounts created by
//!   receiving funds are `Unclaimed` until the owner reveals the matching
//!   policy on first spend.
//! - Transactions declare access sets so the executor can schedule disjoint
//!   transactions in parallel; execution enforces the declaration.
//! - All consensus-critical hashes are domain-separated and length-prefixed
//!   (`Hash::of_tagged`).

pub mod account;
pub mod block;
pub mod hash;
pub mod merkle;
pub mod transaction;

pub use account::{Account, AccountId, AuthPolicy};
pub use block::{Block, BlockHeader};
pub use hash::Hash;
pub use merkle::MerkleProof;
pub use transaction::{AccessSet, AuthReveal, Transaction, TransactionKind};
