use crate::internal::arithmetic::*;
use crate::low_level::elgamal::*;

/// ElGamal ciphertext on which the three PEP operations can be performed:
/// - [rerandomize]: change encrypted representation, same contents when decrypted;
/// - [reshuffle]: change encrypted representation, different contents when decrypted;
/// - [rekey]: change encrypted representation, can be decrypted by a different key.

/// Change encrypted representation using [ScalarNonZero] `r`, same contents when decrypted.
#[cfg(not(feature = "elgamal2"))]
pub fn rerandomize(m: &ElGamal, r: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: r * G + m.gb,
        gc: r * m.gy + m.gc,
        gy: m.gy,
    }
}
#[cfg(feature = "elgamal2")]
pub fn rerandomize(m: &ElGamal, gy: &GroupElement, r: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: r * G + m.gb,
        gc: r * gy + m.gc,
    }
}

/// Change encrypted representation using [ScalarNonZero] `s` so that it has different contents when decrypted equal to `s*msg`, if the original encrypted message was [GroupElement] `msg`.
pub fn reshuffle(m: &ElGamal, s: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: s * m.gb,
        gc: s * m.gc,
        #[cfg(not(feature = "elgamal2"))]
        gy: m.gy,
    }
}

/// Change encrypted representation using [ScalarNonZero] `k`, so it can be decrypted by a different key `k*y` if the input can be decrypted by [ScalarNonZero] `y`.
pub fn rekey(m: &ElGamal, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: k.invert() * m.gb,
        gc: m.gc,
        #[cfg(not(feature = "elgamal2"))]
        gy: k * m.gy,
    }
}

/// Combination of `reshuffle(s)` and `rekey(k)`
pub fn rsk(m: &ElGamal, s: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: (s * k.invert()) * m.gb,
        gc: s * m.gc,
        #[cfg(not(feature = "elgamal2"))]
        gy: k * m.gy,
    }
}

/// Combination of `rerandomize(r)`, `reshuffle(s)` and `rekey(k)`
#[cfg(not(feature = "elgamal2"))]
pub fn rrsk(m: &ElGamal, r: &ScalarNonZero, s: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    let ski = s * k.invert();
    ElGamal {
        gb: ski * m.gb + ski * r * G,
        gc: (s * r) * m.gy + s * m.gc,
        gy: k * m.gy,
    }
}

#[cfg(feature = "elgamal2")]
pub fn rrsk(
    m: &ElGamal,
    gy: &GroupElement,
    r: &ScalarNonZero,
    s: &ScalarNonZero,
    k: &ScalarNonZero,
) -> ElGamal {
    let ski = s * k.invert();
    ElGamal {
        gb: ski * m.gb + ski * r * G,
        gc: (s * r) * gy + s * m.gc,
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

#[cfg(not(feature = "elgamal2"))]
pub fn rrsk2(
    m: &ElGamal,
    r: &ScalarNonZero,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
) -> ElGamal {
    let s = s_from.invert() * s_to;
    let k = k_from.invert() * k_to;
    rrsk(m, &r, &s, &k)
}
#[cfg(feature = "elgamal2")]
pub fn rrsk2(
    m: &ElGamal,
    gy: &GroupElement,
    r: &ScalarNonZero,
    s_from: &ScalarNonZero,
    s_to: &ScalarNonZero,
    k_from: &ScalarNonZero,
    k_to: &ScalarNonZero,
) -> ElGamal {
    let s = s_from.invert() * s_to;
    let k = k_from.invert() * k_to;
    rrsk(m, gy, &r, &s, &k)
}
