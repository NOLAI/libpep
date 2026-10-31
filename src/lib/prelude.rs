//! The imports a typical application needs, and role-specific subsets of them.
//!
//! `use libpep::prelude::*;` brings in the ristretto255 group and ciphersuite, the contexts, the
//! simple data types and the traits to call methods on them, the keys, the factor secrets and
//! info, and the client and transcryptor operations. Features add their items: long variants
//! (`long`), offline encryption (`offline`), batches (`batch`) and verification (`verifiable`).
//!
//! The types and the key functions are the ristretto255 instances from
//! [`ristretto255`](crate::ristretto255): `Pseudonym` is `Pseudonym<Ristretto255>`, and
//! `make_global_keys(rng)` needs no type parameter. The generic items are at their own paths
//! (for example [`data::simple::Pseudonym`](crate::data::simple::Pseudonym)); import those
//! explicitly to work with another group. An explicit import takes precedence over the glob.
//!
//! Left out on purpose, because they are rarely needed or ambiguous when glob-imported: the
//! ElGamal internals, the proofs ([`elgamal::dleq`](crate::elgamal), `elgamal::zkps`), hashing,
//! the [`Group`](crate::elgamal::arithmetic::Group) and
//! [`Ciphersuite`](crate::elgamal::arithmetic::Ciphersuite) traits, the individual factor and key
//! types, and records and JSON documents. Import those from their modules.
//!
//! There are two subsets, each enough for its role:
//! - [`client`]: encryption and decryption
//! - [`transcryptor`]: pseudonymization, rekeying and transcryption
//!
//! Items in more than one prelude are the same item, so the globs can be combined.
//!
//! # Examples
//!
//! ```
//! use libpep::prelude::*;
//!
//! let rng = &mut rand::rng();
//! let (_global_public, global_secret) = make_global_keys(rng);
//! let transcryptor = Transcryptor::new(
//!     PseudonymizationSecret::from(b"pseudonymization secret".to_vec()),
//!     EncryptionSecret::from(b"encryption secret".to_vec()),
//! );
//!
//! let (domain_a, session_a) = (PseudonymizationDomain::from("hospital"), EncryptionContext::from("session-a"));
//! let (domain_b, session_b) = (PseudonymizationDomain::from("research"), EncryptionContext::from("session-b"));
//! let keys_a = make_session_keys(&global_secret, &session_a, transcryptor.rekeying_secret());
//! let keys_b = make_session_keys(&global_secret, &session_b, transcryptor.rekeying_secret());
//!
//! let pseudonym = Pseudonym::random(rng);
//! let encrypted = encrypt(&pseudonym, &keys_a.public(), rng);
//!
//! let info = transcryptor.transcryption_info(&domain_a, &domain_b, &session_a, &session_b);
//! # #[cfg(not(feature = "elgamal3"))]
//! let transcrypted = transcrypt(&encrypted, &info, &keys_a.public(), rng);
//! # #[cfg(feature = "elgamal3")]
//! # let transcrypted = transcrypt(&encrypted, &info, rng);
//!
//! # #[cfg(not(feature = "elgamal3"))]
//! let pseudonym_b = decrypt(&transcrypted, &keys_b);
//! # #[cfg(feature = "elgamal3")]
//! # let pseudonym_b = decrypt(&transcrypted, &keys_b).unwrap();
//! assert_ne!(pseudonym, pseudonym_b);
//! ```

pub use crate::client::prelude::*;
pub use crate::transcryptor::prelude::*;

pub use crate::ristretto255::{
    make_attribute_global_keys, make_attribute_session_keys, make_global_keys,
    make_pseudonym_global_keys, make_pseudonym_session_keys, make_session_keys, GlobalSecretKeys,
};
#[cfg(feature = "verifiable")]
pub use crate::ristretto255::{Verifier, VerifyError};

pub mod client {
    //! Client prelude for encryption and decryption operations.
    pub use crate::client::prelude::*;
}

pub mod transcryptor {
    //! Transcryptor prelude for pseudonymization, rekeying, and transcryption operations.
    pub use crate::transcryptor::prelude::*;
}
