//! Core protocol types for Phi: hashes, accounts, transactions, blocks.
//!
//! Design notes (see docs/SPECIFICATION.md):
//! - Every account is a smart account (native account abstraction). In this
//!   starter, authentication is modeled by an `AuthPolicy` enum that will grow
//!   into passkey/session-key/threshold verification in `phi-vm`.
//! - Transactions declare access sets so the executor can schedule disjoint
//!   transactions in parallel. The starter executor is serial but conflict
//!   detection is already exercised in `phi-mempool`.

pub mod account;
pub mod block;
pub mod hash;
pub mod transaction;

pub use account::{Account, AccountId, AuthPolicy};
pub use block::{Block, BlockHeader};
pub use hash::Hash;
pub use transaction::{AccessSet, Transaction, TransactionKind};
