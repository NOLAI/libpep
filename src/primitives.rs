use crate::arithmetic::*;
use crate::elgamal::*;

/// ElGamal ciphertext on which the three PEP operations can be performed:
/// - [rerandomize]: change encrypted representation, same contents when decrypted;
/// - [reshuffle]: change encrypted representation, different contents when decrypted;
/// - [rekey]: change encrypted representation, can be decrypted by a different key.
///
/// Change encrypted representation using [ScalarNonZero] `s`, same contents when decrypted.
pub fn rerandomize(v: &ElGamal, s: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: s * G + v.b,
        c: s * v.y + v.c,
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

/// Change encrypted representation using [ScalarNonZero] `n` so that is has different contents when decrypted equal to `n*msg`, if the original encrypted message was [GroupElement] `msg`.
pub fn reshuffle(v: &ElGamal, n: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: n * v.b,
        c: n * v.c,
        y: v.y,
    }
}

pub fn reshuffle_from_to(v: &ElGamal, n_from: &ScalarNonZero, n_to: &ScalarNonZero) -> ElGamal {
    let n = n_from.invert() * n_to;
    reshuffle(v, &n)
}


/// Combination of `rekey(k)` and `reshuffle(n)`
pub fn rsk(v: &ElGamal, n: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: (n * k.invert()) * v.b,
        c: n * v.c,
        y: k * v.y,
    }
}

pub fn rsk_from_to(v: &ElGamal, n_from: &ScalarNonZero, n_to: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    let n = n_from.invert() * n_to;
    rsk(v, &n, k)
}

