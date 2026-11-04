//! Client prelude: what a client needs to encrypt, decrypt and hold session keys.
//!
//! It names the ristretto255 group and ciphersuite, the contexts, the data types and the traits to
//! call methods on them, the keys a client holds, and the client operations. The types are the
//! generic ones, whose type parameter defaults to ristretto255, so none is written. The items it
//! shares with the [transcryptor prelude](crate::transcryptor::prelude) are the same items, so
//! both can be glob-imported together. Keys come from the setup or from session key shares
//! ([`Distributed`]); key generation is in [`crate::keys`].
//!
//! # Examples
//!
//! ```
//! use libpep::prelude::client::*;
//! // The setup that hands a client its session keys is not part of the client role.
//! use libpep::factors::RekeyingSecret;
//! use libpep::keys::{make_global_keys, make_session_keys};
//!
//! let rng = &mut rand::rng();
//! let (_, global_secret) = make_global_keys(rng);
//! let secret = RekeyingSecret::from(b"secret".to_vec());
//! let keys = make_session_keys(&global_secret, &EncryptionContext::from("session"), &secret);
//!
//! let client = Client::new(keys);
//! let pseudonym = Pseudonym::random(rng);
//! let encrypted = client.encrypt(&pseudonym, rng);
//! # #[cfg(not(feature = "elgamal3"))]
//! assert_eq!(client.decrypt(&encrypted), pseudonym);
//! # #[cfg(feature = "elgamal3")]
//! # assert_eq!(client.decrypt(&encrypted), Some(pseudonym));
//! ```

pub use crate::ciphersuite::Ristretto255Sha512;
#[cfg(all(feature = "offline", feature = "insecure"))]
pub use crate::client::decrypt_global;
#[cfg(all(feature = "batch", feature = "offline", feature = "insecure"))]
pub use crate::client::decrypt_global_batch;
#[cfg(feature = "offline")]
pub use crate::client::encrypt_global;
#[cfg(all(feature = "batch", feature = "offline"))]
pub use crate::client::encrypt_global_batch;
#[cfg(feature = "offline")]
pub use crate::client::OfflineClient;
pub use crate::client::{decrypt, encrypt, Client, Distributed};
#[cfg(feature = "batch")]
pub use crate::client::{decrypt_batch, encrypt_batch};
pub use crate::contexts::{EncryptionContext, PseudonymizationDomain};
pub use crate::data::elgamal::{ElGamalEncryptable, ElGamalEncrypted};
#[cfg(feature = "long")]
pub use crate::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
pub use crate::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
pub use crate::data::traits::{Encryptable, Encrypted};
pub use crate::group::Ristretto255;
pub use crate::keys::{GlobalPublicKeys, PublicKey, SecretKey, SessionKeys, SessionPublicKeys};
