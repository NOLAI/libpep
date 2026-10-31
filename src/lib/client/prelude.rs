//! Client prelude: what a client needs to encrypt, decrypt and hold session keys.
//!
//! It names the ristretto255 group and ciphersuite, the contexts, the data types and the traits to
//! call methods on them, the keys a client holds, and the client operations. The types are the
//! [ristretto255 instances](crate::ristretto255) of the generic ones, so no type parameter is
//! written. The items it shares
//! with the [transcryptor prelude](crate::transcryptor::prelude) are the same items, so both can
//! be glob-imported together. Keys come from the setup or from session key shares
//! ([`Distributed`]); key generation is in [`crate::keys`].
//!
//! # Examples
//!
//! ```
//! use libpep::prelude::client::*;
//! // The setup that hands a client its session keys is not part of the client role.
//! use libpep::ristretto255::{make_global_keys, make_session_keys, EncryptionSecret};
//!
//! let rng = &mut rand::rng();
//! let (_, global_secret) = make_global_keys(rng);
//! let secret = EncryptionSecret::from(b"secret".to_vec());
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

#[cfg(all(feature = "offline", feature = "insecure"))]
pub use crate::client::decrypt_global;
#[cfg(all(feature = "batch", feature = "offline", feature = "insecure"))]
pub use crate::client::decrypt_global_batch;
#[cfg(feature = "offline")]
pub use crate::client::encrypt_global;
#[cfg(all(feature = "batch", feature = "offline"))]
pub use crate::client::encrypt_global_batch;
pub use crate::client::{decrypt, encrypt, Distributed};
#[cfg(feature = "batch")]
pub use crate::client::{decrypt_batch, encrypt_batch};
pub use crate::contexts::{EncryptionContext, PseudonymizationDomain};
pub use crate::data::elgamal::{ElGamalEncryptable, ElGamalEncrypted};
pub use crate::data::traits::{Encryptable, Encrypted};
#[cfg(feature = "offline")]
pub use crate::ristretto255::OfflineClient;
pub use crate::ristretto255::{
    Attribute, Client, EncryptedAttribute, EncryptedPseudonym, GlobalPublicKeys, Pseudonym,
    Ristretto255, Ristretto255Sha512, SessionKeys, SessionPublicKeys,
};
#[cfg(feature = "long")]
pub use crate::ristretto255::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
