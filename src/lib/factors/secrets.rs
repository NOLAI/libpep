//! Secrets from which pseudonymization and rekeying factors are derived.

/// A secret is a byte string of arbitrary length, from which the pseudonymization and rekeying
/// factors of the contexts are derived.
pub type Secret = Box<[u8]>;

/// Pseudonymization secret used to derive a [`ReshuffleFactor`](super::ReshuffleFactor) from a
/// [`PseudonymizationDomain`](crate::contexts::PseudonymizationDomain).
///
/// All reshuffle factors of a transcryptor derive from this secret; leaking it makes pseudonyms
/// linkable across every domain that transcryptor serves.
#[derive(Clone)]
pub struct PseudonymizationSecret(pub(crate) Secret);

/// Encryption secret used to derive rekey factors from an
/// [`EncryptionContext`](crate::contexts::EncryptionContext).
#[derive(Clone)]
pub struct EncryptionSecret(pub(crate) Secret);

redacted_debug!(PseudonymizationSecret, EncryptionSecret);
zeroize_fields!(PseudonymizationSecret { 0 }, EncryptionSecret { 0 });

impl Drop for PseudonymizationSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl Drop for EncryptionSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for PseudonymizationSecret {}
impl zeroize::ZeroizeOnDrop for EncryptionSecret {}

macro_rules! impl_secret {
    ($t:ident) => {
        impl From<Secret> for $t {
            fn from(secret: Secret) -> Self {
                Self(secret)
            }
        }

        impl From<Vec<u8>> for $t {
            fn from(secret: Vec<u8>) -> Self {
                Self(secret.into_boxed_slice())
            }
        }

        impl From<&[u8]> for $t {
            fn from(secret: &[u8]) -> Self {
                Self(secret.into())
            }
        }

        impl $t {
            /// The secret bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

impl_secret!(PseudonymizationSecret);
impl_secret!(EncryptionSecret);

#[cfg(test)]
mod zeroize_tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn wiping_a_secret_clears_its_bytes() {
        let mut secret = EncryptionSecret::from("a secret".as_bytes());
        secret.zeroize();
        assert!(secret.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn secrets_print_redacted() {
        let secret = PseudonymizationSecret::from("a secret".as_bytes());
        assert_eq!(format!("{secret:?}"), "PseudonymizationSecret([redacted])");
    }
}
