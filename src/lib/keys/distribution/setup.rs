//! System setup for distributed transcryptors: blinding factors and blinded global secret keys.
//!
//! This module provides functions to set up a distributed system with multiple transcryptors.
//! The setup is generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the functions in this module set up a ristretto255 system, as there is nothing to infer the
//! group from.

pub mod generic;

use super::blinding::*;
use crate::keys::types::*;
use rand_core::{CryptoRng, Rng};

/// Setup a distributed system with pseudonym global keys, a blinded global secret key and a list of
/// blinding factors for pseudonyms.
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::transcryptor::DistributedTranscryptor)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`Client`](crate::client::Client)s.
pub fn make_distributed_pseudonym_global_keys<R: Rng + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    PseudonymGlobalPublicKey,
    BlindedPseudonymGlobalSecretKey,
    Vec<BlindingFactor>,
) {
    generic::make_distributed_pseudonym_global_keys(n, rng)
}

/// Setup a distributed system with attribute global keys, a blinded global secret key and a list of
/// blinding factors for attributes.
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::transcryptor::DistributedTranscryptor)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`Client`](crate::client::Client)s.
pub fn make_distributed_attribute_global_keys<R: Rng + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    AttributeGlobalPublicKey,
    BlindedAttributeGlobalSecretKey,
    Vec<BlindingFactor>,
) {
    generic::make_distributed_attribute_global_keys(n, rng)
}

/// Setup a distributed system with both pseudonym and attribute global keys, blinded global secret keys,
/// and a list of blinding factors. This is a convenience method that combines
/// [`make_distributed_pseudonym_global_keys`] and [`make_distributed_attribute_global_keys`].
///
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::transcryptor::DistributedTranscryptor)s),
/// the global public keys and blinded global secret keys can be publicly shared with anyone and are
/// required by [`Client`](crate::client::Client)s.
pub fn make_distributed_global_keys<R: Rng + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    GlobalPublicKeys,
    BlindedGlobalSecretKeys,
    Vec<BlindingFactor>,
) {
    generic::make_distributed_global_keys(n, rng)
}
