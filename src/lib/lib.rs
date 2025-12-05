//! # `libpep`: Library for polymorphic pseudonymization and encryption
//!
//! This library implements PEP cryptography based on [`ElGamal`](base::elgamal) encrypted messages.
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
//! This library provides both a [base] API for `ElGamal` encryption and the PEP
//! [primitives](base::primitives), and a [core] API for
//! [pseudonymization](core::transcryption::ops::pseudonymize) and [rekeying](core::transcryption::ops::rekey)
//! (i.e. [transcryption](core::transcryption::ops::transcrypt)) of [`Pseudonym`](core::data::Pseudonym)s
//! and [`Attribute`](core::data::Attribute)s using this cryptographic concept.
//!
//! The PEP framework was initially described in the article by Eric Verheul and Bart Jacobs,
//! *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*.
//! In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172.
//! [PDF](https://repository.ubn.ru.nl/bitstream/handle/2066/178461/178461.pdf?sequence=1)
//!
//! This library implements an extension of the PEP framework, called *n-PEP*, described in the
//! article by [Job Doesburg](https://jobdoesburg.nl), [Bernard van Gastel](https://sustainablesoftware.info)
//! and [Erik Poll](http://www.cs.ru.nl/~erikpoll/) (to be published).
//!
//! ## Feature flags
//!
//! **Note:** The `python` and `wasm` features are mutually exclusive. If both are enabled,
//! neither binding module will be compiled. This is because PyO3 builds a cdylib that links
//! to the Python interpreter, while wasm-bindgen builds a cdylib targeting WebAssembly -
//! they have incompatible linking requirements.

pub mod arithmetic;
pub mod base;
pub mod core;
pub mod distributed;

#[cfg(all(feature = "python", not(feature = "wasm")))]
pub mod py;

#[cfg(all(feature = "wasm", not(feature = "python")))]
pub mod wasm;
