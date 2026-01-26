//! System setup for distributed transcryptors: blinding factors and blinded global secret keys.
//!
//! This module provides functions to set up a distributed system with multiple transcryptors.

use super::blinding::*;
use crate::keys::*;
use rand_core::{CryptoRng, RngCore};

/// Generic function to setup a distributed system with global keys, blinded global secret key and blinding factors.
fn make_distributed_global_keys_generic<R, PK, SK, F>(
    n: usize,
    rng: &mut R,
    make_keys: F,
    make_blinded: fn(&SK, &[BlindingFactor]) -> Option<SK::BlindedType>,
) -> (PK, SK::BlindedType, Vec<BlindingFactor>)
where
    R: RngCore + CryptoRng,
    F: Fn(&mut R) -> (PK, SK),
    SK: BlindableGlobalSecretKey,
{
    let (pk, sk) = make_keys(rng);
    let blinding_factors: Vec<BlindingFactor> =
        (0..n).map(|_| BlindingFactor::random(rng)).collect();
    // Unwrap is safe: only fails if product of random blinding factors equals 1 (cryptographically negligible)
    #[allow(clippy::unwrap_used)]
    let bsk = make_blinded(&sk, &blinding_factors).unwrap();
    (pk, bsk, blinding_factors)
}

/// Setup a distributed system with pseudonym global keys, a blinded global secret key and a list of
/// blinding factors for pseudonyms.
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::core::transcryptor::DistributedTranscryptor)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`Client`](crate::core::client::Client)s.
pub fn make_distributed_pseudonym_global_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    PseudonymGlobalPublicKey,
    BlindedPseudonymGlobalSecretKey,
    Vec<BlindingFactor>,
) {
    make_distributed_global_keys_generic(
        n,
        rng,
        make_pseudonym_global_keys,
        make_blinded_pseudonym_global_secret_key,
    )
}

/// Setup a distributed system with attribute global keys, a blinded global secret key and a list of
/// blinding factors for attributes.
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::core::transcryptor::DistributedTranscryptor)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`Client`](crate::core::client::Client)s.
pub fn make_distributed_attribute_global_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    AttributeGlobalPublicKey,
    BlindedAttributeGlobalSecretKey,
    Vec<BlindingFactor>,
) {
    make_distributed_global_keys_generic(
        n,
        rng,
        make_attribute_global_keys,
        make_blinded_attribute_global_secret_key,
    )
}

/// Setup a distributed system with both pseudonym and attribute global keys, blinded global secret keys,
/// and a list of blinding factors. This is a convenience method that combines
/// [`make_distributed_pseudonym_global_keys`] and [`make_distributed_attribute_global_keys`].
///
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::core::transcryptor::DistributedTranscryptor)s),
/// the global public keys and blinded global secret keys can be publicly shared with anyone and are
/// required by [`Client`](crate::core::client::Client)s.
pub fn make_distributed_global_keys<R: RngCore + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (GlobalPublicKeys, BlindedGlobalKeys, Vec<BlindingFactor>) {
    let (pseudonym_pk, pseudonym_sk) = make_pseudonym_global_keys(rng);
    let (attribute_pk, attribute_sk) = make_attribute_global_keys(rng);

    let blinding_factors: Vec<BlindingFactor> =
        (0..n).map(|_| BlindingFactor::random(rng)).collect();

    // Unwrap is safe: only fails if product of random blinding factors equals 1 (cryptographically negligible)
    #[allow(clippy::unwrap_used)]
    let blinded_global_keys =
        make_blinded_global_keys(&pseudonym_sk, &attribute_sk, &blinding_factors).unwrap();

    (
        GlobalPublicKeys {
            pseudonym: pseudonym_pk,
            attribute: attribute_pk,
        },
        blinded_global_keys,
        blinding_factors,
    )
}
