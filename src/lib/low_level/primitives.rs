//! PEP primitives for [rekey]ing, [reshuffle]ing, [rerandomize]ation of [ElGamal] ciphertexts, their
//! transitive and reversible n-PEP extensions, and combined versions.

use crate::internal::arithmetic::*;
use crate::low_level::elgamal::*;

/// Change the representation of a ciphertext without changing the contents.
/// Used to make multiple unlinkable copies of the same ciphertext (when disclosing a single
/// stored message multiple times).
#[cfg(feature = "elgamal3")]
pub fn rerandomize(encrypted: &ElGamal, r: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: r * G + encrypted.gb,
        gc: r * encrypted.gy + encrypted.gc,
        gy: encrypted.gy,
    }
}
/// Change the representation of a ciphertext without changing the contents.
/// Used to make multiple unlinkable copies of the same ciphertext (when disclosing a single
/// stored message multiple times).
/// Requires the public key `gy` that was used to encrypt the message to be provided.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize(encrypted: &ElGamal, gy: &GroupElement, r: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: r * G + encrypted.gb,
        gc: r * gy + encrypted.gc,
    }
}

/// Change the contents of a ciphertext with factor `s`, i.e. message `M` becomes `s * M`.
/// Can be used to blindly and pseudo-randomly pseudonymize identifiers.
pub fn reshuffle(encrypted: &ElGamal, s: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: s * encrypted.gb,
        gc: s * encrypted.gc,
        #[cfg(feature = "elgamal3")]
        gy: encrypted.gy,
    }
}

/// Make a message encrypted under one key decryptable under another key.
/// If the original message was encrypted under key `Y`, the new message will be encrypted under key
/// `k * Y` such that users with secret key `k * y` can decrypt it.
pub fn rekey(encrypted: &ElGamal, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: k.invert() * encrypted.gb, // TODO k.invert can be precomputed
        gc: encrypted.gc,
        #[cfg(feature = "elgamal3")]
        gy: k * encrypted.gy,
    }
}

/// Combination of  [`reshuffle`] and [`rekey`] (more efficient and secure than applying them
/// separately).
pub fn rsk(encrypted: &ElGamal, s: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    ElGamal {
        gb: (s * k.invert()) * encrypted.gb, // TODO s * k.invert can be precomputed
        gc: s * encrypted.gc,
        #[cfg(feature = "elgamal3")]
        gy: k * encrypted.gy,
    }
}

/// Combination of [`rerandomize`], [`reshuffle`] and [`rekey`] (more efficient and secure than
/// applying them separately).
#[cfg(feature = "elgamal3")]
pub fn rrsk(m: &ElGamal, r: &ScalarNonZero, s: &ScalarNonZero, k: &ScalarNonZero) -> ElGamal {
    let ski = s * k.invert();
    ElGamal {
        gb: ski * m.gb + ski * r * G,
        gc: (s * r) * m.gy + s * m.gc,
        gy: k * m.gy,
    }
}

/// Combination of [`rerandomize`], [`reshuffle`] and [`rekey`] (more efficient and secure than
/// applying them separately).
#[cfg(not(feature = "elgamal3"))]
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

/// A transitive and reversible n-PEP extension of [`reshuffle`], reshuffling from one pseudonym to
/// another.
pub fn reshuffle2(m: &ElGamal, s_from: &ScalarNonZero, s_to: &ScalarNonZero) -> ElGamal {
    let s = s_from.invert() * s_to;
    reshuffle(m, &s)
}
/// A transitive and reversible n-PEP extension of [`rekey`], rekeying from one key to
/// another.
pub fn rekey2(m: &ElGamal, k_from: &ScalarNonZero, k_to: &ScalarNonZero) -> ElGamal {
    let k = k_from.invert() * k_to;
    rekey(m, &k)
}

/// A transitive and reversible n-PEP extension of [`rsk`].
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

/// A transitive and reversible n-PEP extension of [`rrsk`].
#[cfg(feature = "elgamal3")]
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
    rrsk(m, r, &s, &k)
}
/// A transitive and reversible n-PEP extension of [`rrsk`].
#[cfg(not(feature = "elgamal3"))]
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
    rrsk(m, gy, r, &s, &k)
}
