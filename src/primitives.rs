use crate::arithmetic::*;
use crate::elgamal::*;

/// ElGamal ciphertext on which the three PEP operations can be performed:
/// - [rerandomize]: change encrypted representation, same contents when decrypted;
/// - [reshuffle]: change encrypted representation, different contents when decrypted;
/// - [rekey]: change encrypted representation, can be decrypted by a different key.
///
/// Change encrypted representation using [ScalarNonZero] `r`, same contents when decrypted.
#[cfg(not(feature = "elgamal2"))]
pub fn rerandomize(v: &ElGamal, r: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: r * G + v.b,
        c: r * v.y + v.c,
        y: v.y,
    }
}
// TODO: Rerandomization is in fact possible with the ElGamal2 scheme, but then public key `y` should be provided as an argument
// When using one-directional encryption (towards a global public key), this is actually feasible, but not when using two-directional encryption (towards a session key)

/// Change encrypted representation using [ScalarNonZero] `k`, so it can be decrypted by a different key `k*y` if the input can be decrypted by [ScalarNonZero] `y`.
pub fn rekey(v: &ElGamal, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: k.invert() * v.b,
        c: v.c,
        #[cfg(not(feature = "elgamal2"))]
        y: k * v.y,
    }
}

/// Change encrypted representation using [ScalarNonZero] `s` so that it has different contents when decrypted equal to `s*msg`, if the original encrypted message was [GroupElement] `msg`.
pub fn reshuffle(v: &ElGamal, s: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: s * v.b,
        c: s * v.c,
        #[cfg(not(feature = "elgamal2"))]
        y: v.y,
    }
}

pub fn rekey_from_to(v: &ElGamal, k_from: &ScalarNonZero, k_to: &ScalarNonZero) -> ElGamal {
    let k = k_from.invert() * k_to;
    rekey(v, &k)
}


pub fn reshuffle_from_to(v: &ElGamal, n_from: &ScalarNonZero, n_to: &ScalarNonZero) -> ElGamal {
    let n = n_from.invert() * n_to;
    reshuffle(v, &n)
}


/// Combination of `rekey(k)` and `reshuffle(s)`
pub fn rsk(v: &ElGamal, s: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: (s * k.invert()) * v.b,
        c: s * v.c,
        #[cfg(not(feature = "elgamal2"))]
        y: k * v.y,
    }
}

pub fn rsk_from_to(v: &ElGamal, s_from: &ScalarNonZero, s_to: &ScalarNonZero, k_from: &ScalarNonZero, k_to: &ScalarNonZero) -> ElGamal {
    let s = s_from.invert() * s_to;
    let k = k_from.invert() * k_to;
    rsk(v, &s, &k)
}

