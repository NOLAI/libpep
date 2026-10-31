//! Transcryptor prelude: what a transcryptor needs to derive factors and convert encrypted data.
//!
//! It names the ristretto255 group and ciphersuite, the contexts and secrets the factors derive
//! from, the data types and the traits to call methods on them, and the transcryptor operations.
//! The items it shares with the [client prelude](crate::client::prelude) are the same items, so
//! both can be glob-imported together.
//!
//! # Examples
//!
//! ```
//! use libpep::prelude::transcryptor::*;
//!
//! let transcryptor = Transcryptor::<Ristretto255Sha512>::new(
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
//! let _back: TranscryptionInfo<Ristretto255> = info.reverse();
//! ```

pub use crate::contexts::{EncryptionContext, PseudonymizationDomain};
#[cfg(feature = "long")]
pub use crate::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
pub use crate::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
pub use crate::data::traits::{Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
#[cfg(feature = "verifiable")]
pub use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiableRekeyable, VerifiableTranscryptable,
};
pub use crate::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};
pub use crate::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymRekeyInfo, PseudonymizationInfo,
    PseudonymizationSecret, RekeyPublicKey, TranscryptionInfo,
};
#[cfg(feature = "verifiable")]
pub use crate::factors::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
pub use crate::transcryptor::{
    pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt, DistributedTranscryptor,
    Transcryptor, TranscryptorId,
};
#[cfg(feature = "batch")]
pub use crate::transcryptor::{pseudonymize_batch, rekey_batch, transcrypt_batch};
