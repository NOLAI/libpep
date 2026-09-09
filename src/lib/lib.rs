//! # `libpep`: Library for polymorphic pseudonymization and encryption
//!
//! This library implements PEP cryptography based on [`ElGamal`](core::elgamal) encrypted messages.
//! It can be used to encrypt data and re-encrypt it for different keys without decrypting the data,
//! while pseudonymizing encrypted identifiers in the data.
//!
//! In the `ElGamal` scheme, a message `M` can be encrypted for a receiver which has public key `Y`
//! associated with it, belonging to secret key `y`.
//! Using the PEP cryptography, these encrypted messages can blindly be *transcrypted* from one key
//! to another, by a central semi-trusted party, without the need to decrypt the message inbetween.
//! Meanwhile, if the message contains an identifier of a data subject, this identifier can be
//! pseudonymized.
//! This enables end-to-end encrypted data sharing with built-in pseudonymization.
//! Since at the time of initial encryption, the future recipient does not need to be specified,
//! data sharing can be done *asynchronously*. This means that encrypted data can be
//! stored long-term before it is shared at any point in the future.
//!
//! This library provides both a [core] API for `ElGamal` encryption and the PEP
//! [primitives](core::primitives), and a high-level API for
//! [pseudonymization](transcryptor::pseudonymize) and [rekeying](transcryptor::rekey)
//! (i.e. [transcryption](transcryptor::transcrypt)) of [`Pseudonym`](data::simple::Pseudonym)s
//! and [`Attribute`](data::simple::Attribute)s using this cryptographic concept.
//!
//! This library primarily implements the *n-PEP* scheme, described in the paper by
//! [Job Doesburg](https://jobdoesburg.nl), [Bernard van Gastel](https://sustainablesoftware.info)
//! and [Erik Poll](http://www.cs.ru.nl/~erikpoll/),
//! *n-PEP: Secure data sharing with transitive and distributed blind pseudonymization*.
//! In **Security and Trust Management. 22nd International Workshop, STM 2026, Proceedings**,
//! Lecture Notes in Computer Science, Springer.
//!
//! n-PEP extends the original PEP framework, which was initially described in the article by
//! Eric Verheul and Bart Jacobs,
//! *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*.
//! In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172.
//! [PDF](https://repository.ubn.ru.nl/bitstream/handle/2066/178461/178461.pdf?sequence=1)
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
//!
//! **Note:** The `python` and `wasm` features are mutually exclusive. If both are enabled,
//! neither binding module will be compiled. This is because PyO3 builds a cdylib that links
//! to the Python interpreter, while wasm-bindgen builds a cdylib targeting WebAssembly -
//! they have incompatible linking requirements.

pub mod arithmetic;
pub mod client;
pub mod core;
pub mod data;
pub mod factors;
pub mod keys;
pub mod prelude;
pub mod transcryptor;

#[cfg(all(feature = "python", not(feature = "wasm")))]
pub mod py;

#[cfg(all(feature = "wasm", not(feature = "python")))]
pub mod wasm;

#[cfg(all(feature = "python", not(feature = "wasm")))]
use pyo3::prelude::*;

/// Python module for libpep
#[cfg(all(feature = "python", not(feature = "wasm")))]
#[pymodule]
fn libpep(m: &Bound<'_, PyModule>) -> PyResult<()> {
    py::register_module(m)
}
