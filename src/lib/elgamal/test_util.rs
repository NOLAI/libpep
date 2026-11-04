//! Ristretto255 shorthands for the tests of this module.

use crate::group::group_elements::GroupElement;
use crate::group::scalars::ScalarNonZero;
use crate::group::Ristretto255;
use rand_core::{CryptoRng, Rng};

pub(crate) type ElGamal = crate::elgamal::ElGamal<Ristretto255>;

pub(crate) fn encrypt<R: Rng + CryptoRng>(
    gm: &GroupElement,
    gy: &GroupElement,
    rng: &mut R,
) -> ElGamal {
    crate::elgamal::encrypt::<Ristretto255, R>(gm, gy, rng)
}

#[cfg(feature = "elgamal3")]
pub(crate) fn decrypt(encrypted: &ElGamal, y: &ScalarNonZero) -> Option<GroupElement> {
    crate::elgamal::decrypt(encrypted, y)
}

#[cfg(not(feature = "elgamal3"))]
pub(crate) fn decrypt(encrypted: &ElGamal, y: &ScalarNonZero) -> GroupElement {
    crate::elgamal::decrypt(encrypted, y)
}
