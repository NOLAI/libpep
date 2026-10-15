//! # `libpep`: Library for polymorphic pseudonymization and encryption
//!
//! This library implements *n-PEP*, a scheme for end-to-end encrypted, pseudonymized data
//! sharing. Every party knows its data subjects under its own pseudonyms, which cannot be linked
//! to another party's. Encrypted data is blindly re-encrypted (*transcrypted*) for a receiving
//! party by semi-trusted *transcryptors*, which convert the pseudonyms in it to the receiver's
//! domain without decrypting anything. Transcryption can be distributed over `n` transcryptors,
//! so that every transcryptor can independently monitor and block data exchanges, while
//! confidentiality and pseudonym unlinkability hold as long as at least one of them remains
//! uncompromised.
//!
//! The cryptographic background, a quick start and the relation to OPRFs and proxy re-encryption
//! are described in the [README](https://github.com/NOLAI/libpep#readme). The scheme is described
//! in the paper by [Job Doesburg](https://jobdoesburg.nl),
//! [Bernard van Gastel](https://sustainablesoftware.info) and
//! [Erik Poll](http://www.cs.ru.nl/~erikpoll/),
//! *n-PEP: Secure Data Sharing with Transitive and Distributed Blind Pseudonymization*,
//! **Security and Trust Management. 22nd International Workshop, STM 2026, Proceedings**,
//! Lecture Notes in Computer Science, Springer
//! ([PDF](https://jobdoesburg.nl/docs/n-PEP-STM2026.pdf)).
//!
//! ## Organization
//!
//! - [`client`] and [`transcryptor`] are the high-level API for the two roles: encryption and
//!   decryption on one side, [pseudonymization](transcryptor::pseudonymize),
//!   [rekeying](transcryptor::rekey) and [transcryption](transcryptor::transcrypt) on the other.
//!   Both have distributed variants that work with session key shares.
//! - [`data`] holds the [`Pseudonym`](data::simple::Pseudonym) and
//!   [`Attribute`](data::simple::Attribute) types, their encrypted forms, long variants, records
//!   and JSON documents, and the traits the high-level API is generic over.
//! - [`keys`], [`contexts`] and [`factors`] are the key, identifier and factor material that the
//!   two roles exchange.
//! - [`elgamal`] is the low-level layer: the ciphertext, the PEP
//!   [primitives](elgamal::primitives), the group [arithmetic](elgamal::arithmetic), and
//!   [hashing](elgamal::arithmetic::hashing) to the group and to scalars together with the
//!   [`Ciphersuite`](elgamal::arithmetic::Ciphersuite) its domain separation tags are built
//!   from, reached as [`Group::CIPHERSUITE`](elgamal::arithmetic::Group::CIPHERSUITE).
//! - With the `verifiable` feature, [`elgamal::verifiable`] holds the primitives that emit
//!   zero-knowledge proofs, [`verifier`] checks such proofs against factor commitments, and the
//!   high-level layers gain verifiable counterparts of their operations
//!   ([`data::verifiable`]).
//!
//! ## Groups
//!
//! The library is generic over a prime-order group, abstracted as the
//! [`Group`](elgamal::arithmetic::Group) trait (the group API of RFC 9497). Every type that holds
//! group material has a generic version with a `G: Group` parameter in a `generic` submodule
//! next to it ([`data::simple::generic::Pseudonym`], [`keys::types::generic::SessionKeys`],
//! [`transcryptor::types::generic::Transcryptor`], [`elgamal::zkps::generic::Proof`], ...), and
//! the name at the module level is an alias pinning
//! [`Ristretto255`](elgamal::arithmetic::Ristretto255), the only group implemented so far. Code
//! that uses ristretto255 never needs the generic names.
//!
//! ## Feature flags
//!
//! Default features: `long` (pseudonyms and attributes over 15 bytes), `offline` (encryption
//! towards global keys), `batch` (batch transcryption with shuffling) with `batch-pk` (the batch
//! carries the public key), `serde`, `json` (structured data with nested pseudonyms), and
//! `verifiable` (zero-knowledge proofs of transcryption). The `peppy` command-line tool is a
//! separate crate.
//!
//! Optional features and their security implications:
//!
//! - `elgamal3`: ciphertexts additionally encode the public key they were encrypted for, making
//!   decryption with a mismatched key detectable at the cost of larger ciphertexts and slower
//!   operations. **This feature changes API signatures**: decryption functions return an
//!   [`Option`] (or an error for batches) instead of a plain value. The two modes are not
//!   wire-compatible; choose one for your deployment.
//! - `legacy`: compatibility with the legacy PEP repository implementation (different scalar
//!   derivation). Implies `elgamal3`, `offline` and `global-pseudonyms`; only for
//!   interoperability with legacy deployments.
//! - `insecure`: methods that use global *secret* keys directly, such as offline decryption
//!   (`decrypt_global`). In the intended security model the global
//!   secret key is discarded after distributed setup; retaining it to use these methods gives
//!   its holder the ability to decrypt everything. Intended for testing only.
//! - `global-pseudonyms`: allows pseudonyms in a *global* pseudonymization domain (reshuffle
//!   factor 1). Such pseudonyms are linkable across all domains; only use this when that
//!   linkability is an explicit requirement.
//! - `verifiable-derivation`: derive factors from a pair of master secrets with a Carter–Wegman
//!   hash (Section 3.3.1 of the paper), so that a verifier computes any commitment from the
//!   master public keys instead of storing one per factor. The factors are then linear in two
//!   public hashes: knowing one derived factor reveals nothing about another, but knowing two
//!   (n + 1 with n transcryptors) reveals the master secret and so every factor. The same holds
//!   for anything the factors multiply: two pseudonyms of one subject, or two session keys,
//!   give all of them. The default derivation has no such structure, so the published
//!   commitments of `verifiable` are the preferred scheme; this one trades security for
//!   commitment storage.

#![warn(missing_docs)]

#[macro_use]
mod secrecy;

pub mod client;
pub mod contexts;
pub mod data;
pub mod elgamal;
pub mod errors;
pub mod factors;
pub mod keys;
pub mod prelude;
pub mod transcryptor;

/// Runs the README's quick start as a doctest, in the default ciphertext mode it is written for.
#[cfg(all(doctest, not(feature = "elgamal3")))]
#[doc = include_str!("../../README.md")]
pub struct ReadmeDoctests;
#[cfg(feature = "verifiable")]
pub mod verifier;
