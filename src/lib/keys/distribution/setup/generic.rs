//! Distributed system setup generic over the [`Group`].

use super::super::blinding::generic::*;
use crate::elgamal::arithmetic::group::Group;
use crate::keys::generation::generic::{make_attribute_global_keys, make_pseudonym_global_keys};
use crate::keys::traits::SecretKey;
use crate::keys::types::generic::*;
use rand_core::{CryptoRng, Rng};

/// A function that blinds a global secret key with the transcryptors' blinding factors.
type Blinder<SK> = fn(
    &SK,
    &[BlindingFactor<<SK as SecretKey>::Group>],
) -> Option<<SK as BlindableGlobalSecretKey>::BlindedType>;

/// Generic function to setup a distributed system with global keys, blinded global secret key and blinding factors.
fn make_distributed_global_keys_generic<R, PK, SK, F>(
    n: usize,
    rng: &mut R,
    make_keys: F,
    make_blinded: Blinder<SK>,
) -> (PK, SK::BlindedType, Vec<BlindingFactor<SK::Group>>)
where
    R: Rng + CryptoRng,
    F: Fn(&mut R) -> (PK, SK),
    SK: BlindableGlobalSecretKey,
{
    let (pk, sk) = make_keys(rng);
    let blinding_factors: Vec<BlindingFactor<SK::Group>> =
        (0..n).map(|_| BlindingFactor::random(rng)).collect();
    // Unwrap is safe: only fails if product of random blinding factors equals 1 (cryptographically negligible)
    #[allow(clippy::unwrap_used)]
    let bsk = make_blinded(&sk, &blinding_factors).unwrap();
    (pk, bsk, blinding_factors)
}

/// Setup a distributed system with pseudonym global keys, a blinded global secret key and a list of
/// blinding factors for pseudonyms.
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::transcryptor::DistributedTranscryptor)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`Client`](crate::client::Client)s.
pub fn make_distributed_pseudonym_global_keys<G: Group, R: Rng + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    PseudonymGlobalPublicKey<G>,
    BlindedPseudonymGlobalSecretKey<G>,
    Vec<BlindingFactor<G>>,
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
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::transcryptor::DistributedTranscryptor)s), the global public key
/// and blinded global secret key can be publicly shared with anyone and are required by [`Client`](crate::client::Client)s.
pub fn make_distributed_attribute_global_keys<G: Group, R: Rng + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    AttributeGlobalPublicKey<G>,
    BlindedAttributeGlobalSecretKey<G>,
    Vec<BlindingFactor<G>>,
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
/// The blinding factors should securely be transferred to the transcryptors ([`DistributedTranscryptor`](crate::transcryptor::DistributedTranscryptor)s),
/// the global public keys and blinded global secret keys can be publicly shared with anyone and are
/// required by [`Client`](crate::client::Client)s.
pub fn make_distributed_global_keys<G: Group, R: Rng + CryptoRng>(
    n: usize,
    rng: &mut R,
) -> (
    GlobalPublicKeys<G>,
    BlindedGlobalSecretKeys<G>,
    Vec<BlindingFactor<G>>,
) {
    let (pseudonym_pk, pseudonym_sk) = make_pseudonym_global_keys(rng);
    let (attribute_pk, attribute_sk) = make_attribute_global_keys(rng);

    let blinding_factors: Vec<BlindingFactor<G>> =
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
