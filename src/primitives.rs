use crate::arithmetic::*;
use crate::elgamal::*;

/// ElGamal ciphertext on which the three PEP operations can be performed:
/// - [rerandomize]: change encrypted representation, same contents when decrypted;
/// - [reshuffle]: change encrypted representation, different contents when decrypted;
/// - [rekey]: change encrypted representation, can be decrypted by a different key.
///
/// Change encrypted representation using [ScalarNonZero] `r`, same contents when decrypted.
#[cfg(not(feature = "elgamal2"))]
pub fn rerandomize(m: &ElGamal, r: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: r * G + m.b,
        c: r * m.y + m.c,
        y: m.y,
    }
}
#[cfg(feature = "elgamal2")]
pub fn rerandomize(m: &ElGamal, public_key: &GroupElement, r: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: r * G + m.b,
        c: r * public_key + m.c,
    }
}

/// Change encrypted representation using [ScalarNonZero] `s` so that it has different contents when decrypted equal to `s*msg`, if the original encrypted message was [GroupElement] `msg`.
pub fn reshuffle(m: &ElGamal, s: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: s * m.b,
        c: s * m.c,
        #[cfg(not(feature = "elgamal2"))]
        y: m.y,
    }
}

/// Change encrypted representation using [ScalarNonZero] `k`, so it can be decrypted by a different key `k*y` if the input can be decrypted by [ScalarNonZero] `y`.
pub fn rekey(m: &ElGamal, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: k.invert() * m.b,
        c: m.c,
        #[cfg(not(feature = "elgamal2"))]
        y: k * m.y,
    }
}

/// Combination of `rekey(k)` and `reshuffle(s)`
pub fn rsk(m: &ElGamal, s: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: (s * k.invert()) * m.b,
        c: s * m.c,
        #[cfg(not(feature = "elgamal2"))]
        y: k * m.y,
    }
}
pub fn reshuffle2(m: &ElGamal, s_from: &ScalarNonZero, s_to: &ScalarNonZero) -> ElGamal {
    let s = s_from.invert() * s_to;
    reshuffle(m, &s)
}
pub fn rekey2(m: &ElGamal, k_from: &ScalarNonZero, k_to: &ScalarNonZero) -> ElGamal {
    let k = k_from.invert() * k_to;
    rekey(m, &k)
}

pub fn rsk2(
    m: &ElGamal,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
) -> ElGamal {
    let s = s_from.invert() * s_to;
    let k = k_from.invert() * k_to;
    rsk(m, &s, &k)
}
