//! Transcryptor prelude: what a transcryptor needs to derive factors and convert encrypted data.
//!
//! It names the ristretto255 group and ciphersuite, the contexts and secrets the factors derive
//! from, the data types and the traits to call methods on them, and the transcryptor operations.
//! The types are the [ristretto255 instances](crate::ristretto255) of the generic ones, so no type
//! parameter is written.
//! The items it shares with the [client prelude](crate::client::prelude) are the same items, so
//! both can be glob-imported together.
//!
//! # Examples
//!
//! ```
//! use libpep::prelude::transcryptor::*;
//!
//! let transcryptor = Transcryptor::new(
//!     PseudonymizationSecret::from(b"pseudonymization secret".to_vec()),
//!     EncryptionSecret::from(b"encryption secret".to_vec()),
//! );
//! let info = transcryptor.transcryption_info(
//!     &PseudonymizationDomain::from("hospital"),
//!     &PseudonymizationDomain::from("research"),
//!     &EncryptionContext::from("session-a"),
//!     &EncryptionContext::from("session-b"),
//! );
//! // Reversing the info converts back.
//! let _back: TranscryptionInfo = info.reverse();
//! ```

pub use crate::contexts::{EncryptionContext, PseudonymizationDomain};
pub use crate::data::traits::{Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
#[cfg(feature = "verifiable")]
pub use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiableRekeyable, VerifiableTranscryptable,
};
pub use crate::factors::{EncryptionSecret, PseudonymizationSecret, RekeyPublicKey};
pub use crate::ristretto255::{
    Attribute, AttributeRekeyInfo, DistributedTranscryptor, EncryptedAttribute, EncryptedPseudonym,
    Pseudonym, PseudonymRekeyInfo, PseudonymizationInfo, Ristretto255, Ristretto255Sha512,
    TranscryptionInfo, Transcryptor,
};
#[cfg(feature = "long")]
pub use crate::ristretto255::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
#[cfg(feature = "verifiable")]
pub use crate::ristretto255::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
pub use crate::transcryptor::{
    pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt, TranscryptorId,
};
#[cfg(feature = "batch")]
pub use crate::transcryptor::{pseudonymize_batch, rekey_batch, transcrypt_batch};
