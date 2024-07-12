use crate::arithmetic::*;
use crate::elgamal::*;

/// ElGamal ciphertext on which the three PEP operations can be performed:
/// - [rerandomize]: change encrypted representation, same contents when decrypted;
/// - [reshuffle]: change encrypted representation, different contents when decrypted;
/// - [rekey]: change encrypted representation, can be decrypted by a different key.
///
/// Change encrypted representation using [ScalarNonZero] `r`, same contents when decrypted.
pub fn rerandomize(v: &ElGamal, r: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: r * G + v.b,
        c: r * v.y + v.c,
        y: v.y,
    }
}

/// Change encrypted representation using [ScalarNonZero] `k`, so it can be decrypted by a different key `k*y` if the input can be decrypted by [ScalarNonZero] `y`.
pub fn rekey(v: &ElGamal, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: k.invert() * v.b,
        c: v.c,
        y: k * v.y,
    }
}

/// Change encrypted representation using [ScalarNonZero] `s` so that is has different contents when decrypted equal to `s*msg`, if the original encrypted message wasm [GroupElement] `msg`.
pub fn reshuffle(v: &ElGamal, s: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: s * v.b,
        c: s * v.c,
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
        y: k * v.y,
    }
}

pub fn rsk_from_to(v: &ElGamal, s_from: &ScalarNonZero, s_to: &ScalarNonZero, k_from: &ScalarNonZero, k_to: &ScalarNonZero) -> ElGamal {
    let s = s_from.invert() * s_to;
    let k = k_from.invert() * k_to;
    rsk(v, &s, &k)
}

