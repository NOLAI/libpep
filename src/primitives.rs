use hmac::digest::typenum::Gr;
use crate::arithmetic::*;
use crate::elgamal::*;

/// ElGamal ciphertext on which the three PEP operations can be performed:
/// - [rerandomize]: change encrypted representation, same contents when decrypted;
/// - [reshuffle]: change encrypted representation, different contents when decrypted;
/// - [rekey]: change encrypted representation, can be decrypted by a different key.

/// Change encrypted representation using [ScalarNonZero] `r`, same contents when decrypted.
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
    }
}

/// Change encrypted representation using [ScalarNonZero] `k`, so it can be decrypted by a different key `k*y` if the input can be decrypted by [ScalarNonZero] `y`.
pub fn rekey(m: &ElGamal, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: k.invert() * m.b,
        c: m.c,
    }
}

/// Combination of `reshuffle(s)` and `rekey(k)`
pub fn rsk(m: &ElGamal, s: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        b: (s * k.invert()) * m.b,
        c: s * m.c,
    }
}

/// Combination of `rerandomize(r)`, `reshuffle(s)` and `rekey(k)`
pub fn rrsk(m: &ElGamal, public_key: &GroupElement, r: &ScalarNonZero, s: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    let ski = s * k.invert();
    ElGamal {
        b: ski * m.b + ski * r * G,
        c: (s * r) * public_key + s * m.c,
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

pub fn rrsk2(
    m: &ElGamal,
    public_key: &GroupElement,
    r: &ScalarNonZero,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
) -> ElGamal {
    let s = s_from.invert() * s_to;
    let k = k_from.invert() * k_to;
    rrsk(m, public_key, &r, &s, &k)
}
