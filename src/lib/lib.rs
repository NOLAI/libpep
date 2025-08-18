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
//! and [DataPoints](high_level::data_types::DataPoint) using this cryptographic concept.
//!
//! The PEP framework was initially described in the article by Eric Verheul and Bart Jacobs,
//! *Polymorphic Encryption and Pseudonymisation in Identity Management and Medical Research*.
//! In **Nieuw Archief voor Wiskunde (NAW)**, 5/18, nr. 3, 2017, p. 168-172.
//! [PDF](https://repository.ubn.ru.nl/bitstream/handle/2066/178461/178461.pdf?sequence=1)
//!
//! This library implements an extension of the PEP framework, called *n-PEP*, described in the
//! article by [Job Doesburg](https://jobdoesburg.nl), [Bernard van Gastel](https://sustainablesoftware.info)
//! and [Erik Poll](http://www.cs.ru.nl/~erikpoll/) (to be published).

pub mod internal {
    //! Internal API that provides useful wrappers around dependencies, simplifying [arithmetic] operations.
    //! This module is not intended to be used by the end user, except for advanced use cases.
    pub mod arithmetic;
}

pub mod low_level {
    //! Low-level cryptographic [primitives] for [ElGamal](elgamal) encryption and (n)-PEP operations.
    //! This module is intended for non-standard uses cases where the individual (n)-PEP primitives are
    //! needed.
    //!
    //! For most use cases, the [high-level](crate::high_level) API should be used, which provides
    //! a more user-friendly and safer interface.
    pub mod elgamal;
    pub mod primitives;
}
pub mod high_level {
    //! High-level API specifying [Pseudonyms](data_types::Pseudonym) and [DataPoints](data_types::DataPoint),
    //! and [transcryption](ops::transcrypt) ([pseudonymization](ops::pseudonymize) or [rekeying](ops::rekey))
    //! of their encrypted versions between different contexts.
    //! This module is intended for most use cases where a *single* trusted party (transcryptor) is
    //! responsible for pseudonymization and rekeying.
    //! The API is designed to be user-friendly and safe.

    pub mod contexts;
    pub mod data_types;
    pub mod keys;
    pub mod ops;
    pub mod utils;
}
pub mod distributed {
    //! Distributed n-PEP with wrappers for high-level [`PEPSystems`](systems::PEPSystem) (*transcryptors*) and [`PEPClients`](systems::PEPClient).
    //! This module is intended for use cases where transcryption is performed by *n* parties and
    //! trust is distributed among them (i.e. no single party is trusted but the system remains secure
    //! as long as at least 1 party remains honest).

    pub mod key_blinding;
    pub mod systems;
}
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "python")]
mod python;

#[cfg(feature = "python")]
pub use python::libpep;
