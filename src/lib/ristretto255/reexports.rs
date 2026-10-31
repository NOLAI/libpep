//! The items of the generic API that need no instantiation, re-exported next to the aliases:
//! the group and ciphersuite markers, the functions that infer the group from their arguments,
//! the traits to call methods with, the secrets, contexts and errors.

pub use crate::elgamal::arithmetic::group_elements::GroupElement;
pub use crate::elgamal::arithmetic::scalars::{ScalarCanBeZero, ScalarNonZero};
pub use crate::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};

pub use crate::contexts::{EncryptionContext, PseudonymizationDomain, TranscryptorId};
pub use crate::factors::{EncryptionSecret, PseudonymizationSecret, Secret};

// Data.
#[cfg(feature = "batch")]
pub use crate::data::batch::{BatchError, Batchable, EncryptedBatch};
pub use crate::data::elgamal::{ElGamalEncryptable, ElGamalEncrypted};
pub use crate::data::errors::ParseError;
#[cfg(feature = "json")]
pub use crate::data::json::{JsonError, JsonStructure};
pub use crate::data::padding::{Padded, PaddingError};
#[cfg(feature = "long")]
pub use crate::data::records::LongRecordStructure;
pub use crate::data::records::RecordStructure;
#[cfg(feature = "batch")]
pub use crate::data::traits::HasStructure;
pub use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
#[cfg(feature = "verifiable")]
pub use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable, VerifiableTranscryptable, VerifiableTranscryptionProof,
};

// Keys and key distribution.
pub use crate::keys::distribution::{
    make_attribute_session_key_share, make_blinded_attribute_global_secret_key,
    make_blinded_global_key, make_blinded_global_keys, make_blinded_pseudonym_global_secret_key,
    make_pseudonym_session_key_share, make_session_key_share, make_session_key_shares,
    BlindableGlobalSecretKey, BlindedGlobalSecretKey, SessionKeyShare,
};
#[cfg(feature = "verifiable")]
pub use crate::keys::distribution::{make_session_key_share_with_proof, SessionKeyShareError};
pub use crate::keys::{make_global_key_pair, KeyProvider, PublicKey, SecretKey};

// Factors.
pub use crate::factors::{Factor, RekeyPublicKey};

// Client.
#[cfg(all(feature = "batch", feature = "insecure"))]
pub use crate::client::batch::encrypt_batch_raw;
#[cfg(all(feature = "offline", feature = "insecure"))]
pub use crate::client::decrypt_global;
#[cfg(all(feature = "batch", feature = "offline", feature = "insecure"))]
pub use crate::client::decrypt_global_batch;
pub use crate::client::distributed::{
    make_attribute_session_key, make_pseudonym_session_key, make_session_key,
    make_session_keys_distributed, update_attribute_session_key, update_pseudonym_session_key,
    update_session_key, update_session_keys, SessionKeyUpdater,
};
#[cfg(feature = "offline")]
pub use crate::client::encrypt_global;
#[cfg(all(feature = "batch", feature = "offline"))]
pub use crate::client::encrypt_global_batch;
pub use crate::client::{decrypt, encrypt, Distributed};
#[cfg(feature = "batch")]
pub use crate::client::{decrypt_batch, encrypt_batch};

// Transcryptor.
pub use crate::transcryptor::{pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt};
#[cfg(feature = "batch")]
pub use crate::transcryptor::{pseudonymize_batch, rekey_batch, transcrypt_batch};

// Verifier.
#[cfg(feature = "verifiable")]
pub use crate::verifier::{
    CacheRegistrationError, CommitmentsCache, InMemoryCommitmentsCache, PseudonymizationKey,
    RegisterCommitmentsError, RekeyTransitionKey, VerifyError, WeakCommitmentError,
};
