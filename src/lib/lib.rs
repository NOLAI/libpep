//! # `libpep`: Library for polymorphic encryption and pseudonymization
//!
//! This library implements *n-PEP*, a scheme for end-to-end encrypted, asynchronous,
//! pseudonymized data sharing between users. Every user knows its data subjects under its own
//! pseudonyms, which cannot be linked to another user's pseudonyms for the same data subjects.
//! A sender encrypts data without the receiver being online, or even known, at that moment;
//! *transcryptors* later blindly re-encrypt (*transcrypt*) it for the receiver's pseudonymization
//! domain and encryption context, converting the pseudonyms in it without decrypting anything.
//! Transcryption can be distributed over `n` transcryptors, so that every transcryptor can
//! independently monitor and block data exchanges.
//!
//! The transcryptors are *semi-trusted*: no single transcryptor can read data or link
//! pseudonyms, and confidentiality and pseudonym unlinkability hold as long as at least one of
//! the `n` transcryptors remains uncompromised. n-PEP does not guarantee integrity: it does not
//! show that a transcryptor applied the right factors. The `verifiable` feature lets that be
//! checked.
//!
//! The cryptographic background and a quick start
//! are in the [README](https://github.com/NOLAI/libpep#readme). The scheme is described
//! by [Job Doesburg](https://jobdoesburg.nl),
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
//!   [hashing](elgamal::arithmetic::hashing) to the group and to scalars, which runs under a
//!   [`Ciphersuite`](elgamal::arithmetic::Ciphersuite): a group together with the hash and the
//!   identifier its domain separation tags are built from.
//! - [`prelude`] imports what a typical application needs, with subsets for each role.
//! - With the `verifiable` feature, `elgamal::verifiable` holds the primitives that emit
//!   zero-knowledge proofs, `verifier` checks such proofs against factor commitments, and the
//!   high-level layers gain verifiable counterparts of their operations
//!   (`data::verifiable`).
//!
//! ## Groups and ciphersuites
//!
//! The whole API ([`elgamal`], [`data`], [`keys`], [`factors`], [`client`], [`transcryptor`],
//! `verifier`) is generic, in two layers.
//!
//! The data types (`Pseudonym<G>`, `SessionKeys<G>`, ciphertexts, proofs, ...) and the group
//! arithmetic are generic over the prime-order group, abstracted as the
//! [`Group`](elgamal::arithmetic::Group) trait. Whatever hashes is generic over a
//! [`Ciphersuite`](elgamal::arithmetic::Ciphersuite), which pairs a group with a hash: deriving
//! factors, hashing an identifier to the group, creating and verifying proofs, and the roles built
//! on them (`Transcryptor<C>`, `Verifier<C>`). Another group and hash can be used by implementing
//! the two traits.
//!
//! The library is built for ristretto255 with SHA-512,
//! [`Ristretto255`](elgamal::arithmetic::Ristretto255) with
//! [`Ristretto255Sha512`](elgamal::arithmetic::Ristretto255Sha512), and every generic type
//! defaults its parameter to them: `Pseudonym` is `Pseudonym<Ristretto255>` and `Transcryptor` is
//! `Transcryptor<Ristretto255Sha512>`. In the common case no type parameter is written, which is
//! how `peppy` and the Python and JavaScript bindings use the library.
//!
//! ```
//! use libpep::prelude::*;
//!
//! let rng = &mut rand::rng();
//! let (_public, global_secret) = make_global_keys(rng);
//! let transcryptor = Transcryptor::new(
//!     PseudonymizationSecret::from(b"pseudonymization secret".to_vec()),
//!     RekeyingSecret::from(b"rekeying secret".to_vec()),
//! );
//! let session = EncryptionContext::from("session");
//! let keys = make_session_keys(&global_secret, &session, transcryptor.rekeying_secret());
//! let pseudonym = Pseudonym::random(rng);
//! let encrypted = encrypt(&pseudonym, &keys.public(), rng);
//! # #[cfg(not(feature = "elgamal3"))]
//! assert_eq!(decrypt(&encrypted, &keys), pseudonym);
//! # #[cfg(feature = "elgamal3")]
//! # assert_eq!(decrypt(&encrypted, &keys), Some(pseudonym));
//! ```
//!
//! Rust does not use a default type parameter to infer one, so an expression that nothing
//! constrains still needs a type: `Pseudonym::random(rng).to_hex()` does not compile, while
//! `let pseudonym: Pseudonym = Pseudonym::random(rng);` does. The functions and constructors that
//! could never infer their parameter, because it appears only in the result or in an associated
//! type, come in a pair instead:
//!
//! - the plain name is the ristretto255 one, with no type parameter: [`keys::make_global_keys`],
//!   [`keys::make_session_keys`] and the other key functions, [`factors::make_pseudonymization_factor`]
//!   and the other factor functions, [`elgamal::arithmetic::hashing::hash_to_group`],
//!   [`transcryptor::Transcryptor::new`], [`transcryptor::DistributedTranscryptor::new`],
//!   `PseudonymizationInfo::new` (and the other info types), and with the `verifiable` feature
//!   `Verifier::new`, the session key share functions with a proof and the master secrets;
//! - the same name with the suffix `_generic` takes the group or ciphersuite as a type
//!   parameter: `make_global_keys_generic::<G, _>(rng)`, `make_session_keys_generic::<C>(..)`,
//!   `Transcryptor::<C>::new_generic(..)`. The body is written once, in the generic function, and
//!   the plain one calls it.
//!
//! Generic code, and code for another group, uses the `_generic` names. The generic types stay at
//! their own paths, for example [`data::simple::Pseudonym`], and `Pseudonym<OtherGroup>` works
//! like `Pseudonym`.
//!
//! ## Feature flags
//!
//! Default features: `long` (pseudonyms and attributes over 15 bytes), `offline` (encryption
//! towards global keys), `batch` (batch transcryption with shuffling) with `batch-pk` (the batch
//! carries the public key), `serde`, `json` (structured data with nested pseudonyms), and
//! `verifiable` (zero-knowledge proofs of transcryption). The optional `cli` feature builds the
//! `peppy` command-line tool.
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
//! - `verifiable-derivation`: derive factors from a pair of master secrets with a Carter-Wegman
//!   hash, so that a verifier computes any commitment from the master public keys instead of
//!   storing one per factor. The factors are then linear in two
//!   public hashes: knowing one derived factor reveals nothing about another, but knowing two
//!   (n + 1 with n transcryptors) reveals the master secret and so every factor. The same holds
//!   for anything the factors multiply: two pseudonyms of one subject, or two session keys,
//!   give all of them. The default derivation has no such structure, so the published
//!   commitments of `verifiable` are the preferred scheme; this one trades security for
//!   commitment storage.

#![warn(missing_docs)]

pub mod client;
pub mod contexts;
pub mod data;
pub mod elgamal;
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
