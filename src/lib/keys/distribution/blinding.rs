//! Blinding factors and blinded global secret keys for distributed transcryptors.
//!
//! During system setup the global secret keys are blinded with one blinding factor per
//! transcryptor, so that no key can be derived from the published blinded key without the
//! cooperation of every transcryptor.
//!
//! Blinding factors and blinded keys are protocol material, not keys: no data is encrypted
//! towards them and they have no associated public key, so they do not implement
//! [`SecretKey`](crate::keys::SecretKey).
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances. The blinding functions infer the
//! group from the key they blind.

pub mod generic;

pub use generic::{
    make_blinded_attribute_global_secret_key, make_blinded_global_key, make_blinded_global_keys,
    make_blinded_pseudonym_global_secret_key, BlindableGlobalSecretKey, BlindedGlobalSecretKey,
};

use crate::elgamal::arithmetic::Ristretto255;

/// The [`BlindingFactor`](generic::BlindingFactor) over ristretto255.
pub type BlindingFactor = generic::BlindingFactor<Ristretto255>;
/// The [`BlindedPseudonymGlobalSecretKey`](generic::BlindedPseudonymGlobalSecretKey) over ristretto255.
pub type BlindedPseudonymGlobalSecretKey = generic::BlindedPseudonymGlobalSecretKey<Ristretto255>;
/// The [`BlindedAttributeGlobalSecretKey`](generic::BlindedAttributeGlobalSecretKey) over ristretto255.
pub type BlindedAttributeGlobalSecretKey = generic::BlindedAttributeGlobalSecretKey<Ristretto255>;
/// The [`BlindedGlobalSecretKeys`](generic::BlindedGlobalSecretKeys) over ristretto255.
pub type BlindedGlobalSecretKeys = generic::BlindedGlobalSecretKeys<Ristretto255>;
