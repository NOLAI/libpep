//! Client prelude: what a client needs to encrypt, decrypt and hold session keys.
//!
//! It names the ristretto255 group and ciphersuite, the contexts, the data types and the traits to
//! call methods on them, the keys a client holds, and the client operations. The items it shares
//! with the [transcryptor prelude](crate::transcryptor::prelude) are the same items, so both can
//! be glob-imported together. Keys come from the setup or from session key shares
//! ([`Distributed`]); key generation is in [`crate::keys`].
//!
//! # Examples
//!
//! ```
//! use libpep::prelude::client::*;
//! // The setup that hands a client its session keys is not part of the client role.
//! use libpep::keys::{make_global_keys, make_session_keys};
//! use libpep::factors::EncryptionSecret;
//!
//! let rng = &mut rand::rng();
//! let (_, global_secret) = make_global_keys::<Ristretto255, _>(rng);
//! let secret = EncryptionSecret::from(b"secret".to_vec());
//! let keys = make_session_keys::<Ristretto255Sha512>(&global_secret, &EncryptionContext::from("session"), &secret);
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
#[cfg(all(feature = "batch", feature = "offline"))]
pub use crate::client::encrypt_global_batch;
pub use crate::client::{decrypt, encrypt, Client, Distributed};
#[cfg(feature = "batch")]
pub use crate::client::{decrypt_batch, encrypt_batch};
#[cfg(feature = "offline")]
pub use crate::client::{encrypt_global, OfflineClient};
pub use crate::contexts::{EncryptionContext, PseudonymizationDomain};
pub use crate::data::elgamal::{ElGamalEncryptable, ElGamalEncrypted};
#[cfg(feature = "long")]
pub use crate::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
pub use crate::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
pub use crate::data::traits::{Encryptable, Encrypted};
pub use crate::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};
pub use crate::keys::{GlobalPublicKeys, SessionKeys, SessionPublicKeys};
