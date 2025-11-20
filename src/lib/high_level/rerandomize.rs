//! Rerandomization operations for creating binary unlinkable copies of encrypted messages.

use crate::arithmetic::ScalarNonZero;
use crate::high_level::core::*;
use crate::high_level::keys::PublicKey;
use crate::high_level::transcryption::contexts::RerandomizeFactor;
use rand_core::{CryptoRng, RngCore};

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message.
#[cfg(feature = "elgamal3")]
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted>(encrypted: &E, rng: &mut R) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, &RerandomizeFactor(r))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize<R: RngCore + CryptoRng, E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    rng: &mut R,
) -> E {
    let r = ScalarNonZero::random(rng);
    rerandomize_known(encrypted, public_key, &RerandomizeFactor(r))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message,
/// using a known rerandomization factor.
#[cfg(feature = "elgamal3")]
pub fn rerandomize_known<E: Encrypted>(encrypted: &E, r: &RerandomizeFactor) -> E {
    E::from_value(crate::low_level::primitives::rerandomize(
        encrypted.value(),
        &r.0,
    ))
}

/// Rerandomize an encrypted message, i.e. create a binary unlinkable copy of the same message,
/// using a known rerandomization factor.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize_known<E: Encrypted, P: PublicKey>(
    encrypted: &E,
    public_key: &P,
    r: &RerandomizeFactor,
) -> E {
    E::from_value(crate::low_level::primitives::rerandomize(
        encrypted.value(),
        public_key.value(),
        &r.0,
    ))
}
