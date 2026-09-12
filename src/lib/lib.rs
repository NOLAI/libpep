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
//!   [primitives](elgamal::primitives) and the group [arithmetic](elgamal::arithmetic).
//!
//! ## Feature flags
//!
//! Default features: `long` (pseudonyms and attributes over 15 bytes), `offline` (encryption
//! towards global keys), `batch` (batch transcryption with shuffling), `serde`, `json`
//! (structured data with nested pseudonyms), and `build-binary` (the `peppy` CLI).
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
