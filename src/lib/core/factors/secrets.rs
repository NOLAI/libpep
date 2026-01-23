//! Secret types used for deriving cryptographic factors.

use derive_more::From;

/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from contexts.
pub type Secret = Box<[u8]>;

/// Pseudonymization secret used to derive a [`ReshuffleFactor`](super::ReshuffleFactor) from a [`PseudonymizationDomain`](crate::core::factors::contexts::PseudonymizationDomain).
#[derive(Clone, Debug, From)]
pub struct PseudonymizationSecret(pub(crate) Secret);

/// Encryption secret used to derive rekey factors from an [`EncryptionContext`](crate::core::factors::contexts::EncryptionContext).
#[derive(Clone, Debug, From)]
pub struct EncryptionSecret(pub(crate) Secret);

impl PseudonymizationSecret {
    pub fn from(secret: Vec<u8>) -> Self {
        Self(secret.into_boxed_slice())
    }
}

impl EncryptionSecret {
    pub fn from(secret: Vec<u8>) -> Self {
        Self(secret.into_boxed_slice())
    }
}
