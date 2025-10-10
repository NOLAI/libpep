//! # **`libpep`**: Library for polymorphic pseudonymization and encryption
//!
//! This library implements PEP cryptography based on [ElGamal](low_level::elgamal) encrypted messages.
//!
//! In the ElGamal scheme, a message `M` can be encrypted for a receiver which has public key `Y`
//! associated with it, belonging to secret key `y`.
//! Using the PEP cryptography, these encrypted messages can blindly be *transcrypted* from one key
//! to another, by a central semi-trusted party, without the need to decrypt the message in between.
//! Meanwhile, if the message contains an identifier of a data subject, this identifier can be
//! pseudonymized.
//! This enables end-to-end encrypted data sharing with built-in pseudonymization.
//! Additionally, since at time of initial encryption, the future recipient does not need to be
//! specified, data sharing can be done *asynchronously*, which means that encrypted data can be
//! stored long-term before it is shared at any point in the future.
//!
//! This library provides both a [low-level] API for ElGamal encryption and the PEP
//! [primitives](low_level::primitives), and a [high-level] API for
//! [pseudonymization](high_level::ops::pseudonymize) and [rekeying](high_level::ops::rekey)
//! (i.e. [transcryption](high_level::ops::transcrypt)) of [Pseudonyms](high_level::data_types::Pseudonym)
//! and [Attributes](high_level::data_types::Attribute) using this cryptographic concept.
//!
//! The PEP framework was initially described in the article by Eric Verheul and Bart Jacobs,
//! *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*.
//! In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172.
//! [PDF](https://repository.ubn.ru.nl/bitstream/handle/2066/178461/178461.pdf?sequence=1)
//!
//! This library implements an extension of the PEP framework, called *n-PEP*, described in the
//! article by [Job Doesburg](https://jobdoesburg.nl), [Bernard van Gastel](https://sustainablesoftware.info)
//! and [Erik Poll](http://www.cs.ru.nl/~erikpoll/) (to be published).

// Compile-time check to prevent using both python and wasm features together.
// These features are mutually exclusive because:
// 1. PyO3 (python) builds a cdylib that links to Python interpreter
// 2. wasm-bindgen (wasm) builds a cdylib that targets WebAssembly
// 3. Both require different linking strategies and cannot coexist in the same build
// Use `--features python` for Python bindings or `--features wasm` for WASM, but not both.
#[cfg(all(feature = "python", feature = "wasm"))]
compile_error!(
    "Features `python` and `wasm` are mutually exclusive. \
     PyO3 and wasm-bindgen have incompatible linking requirements. \
     Use either `--features python` or `--features wasm`, not both."
);

pub mod distributed;
pub mod high_level;
pub mod internal;
pub mod low_level;
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "python")]
mod python;

#[cfg(feature = "python")]
pub use python::libpep;
