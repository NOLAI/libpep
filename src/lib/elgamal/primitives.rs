//! PEP primitives for [rekey]ing, [reshuffle]ing, [rerandomize]ation of [ElGamal] ciphertexts, their
//! transitive and reversible n-PEP extensions, and combined versions.
//!
//! All primitives are generic over the [`Group`]; the group is inferred from the ciphertext.
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;

/// Change the representation of a ciphertext without changing the contents.
/// Used to make multiple unlinkable copies of the same ciphertext (when disclosing a single
/// stored message multiple times).
#[cfg(feature = "elgamal3")]
pub fn rerandomize<G: Group>(encrypted: &ElGamal<G>, r: &G::Scalar) -> ElGamal<G> {
    ElGamal {
        gb: G::scalar_mult_gen(r) + encrypted.gb,
        gc: *r * encrypted.gy + encrypted.gc,
        gy: encrypted.gy,
    }
}
/// Change the representation of a ciphertext without changing the contents.
/// Used to make multiple unlinkable copies of the same ciphertext (when disclosing a single
/// stored message multiple times).
/// Requires the public key `gy` that was used to encrypt the message to be provided.
#[cfg(not(feature = "elgamal3"))]
pub fn rerandomize<G: Group>(encrypted: &ElGamal<G>, gy: &G::Element, r: &G::Scalar) -> ElGamal<G> {
    ElGamal {
        gb: G::scalar_mult_gen(r) + encrypted.gb,
        gc: *r * *gy + encrypted.gc,
    }
}

/// Change the contents of a ciphertext with factor `s`, i.e. message `M` becomes `s * M`.
/// Can be used to blindly and pseudo-randomly pseudonymize identifiers.
///
/// This is an encryption-based oblivious evaluation of the Diffie–Hellman PRF
/// `F_s(M) = s * M`, which is pseudorandom under the DDH assumption while `s` stays secret:
/// the performing party evaluates the PRF homomorphically without learning `M` or `s * M`,
/// which is what makes the resulting pseudonyms unlinkable across domains.
pub fn reshuffle<G: Group>(encrypted: &ElGamal<G>, s: &G::Scalar) -> ElGamal<G> {
    ElGamal {
        gb: *s * encrypted.gb,
        gc: *s * encrypted.gc,
        #[cfg(feature = "elgamal3")]
        gy: encrypted.gy,
    }
}

/// Make a message encrypted under one key decryptable under another key.
/// If the original message was encrypted under key `Y`, the new message will be encrypted under key
/// `k * Y` such that users with secret key `k * y` can decrypt it.
pub fn rekey<G: Group>(encrypted: &ElGamal<G>, k: &G::Scalar) -> ElGamal<G> {
    let k_inv = G::scalar_inverse(k);
    #[cfg(feature = "elgamal3")]
    return rekey_precomputed(encrypted, k, &k_inv);
    #[cfg(not(feature = "elgamal3"))]
    rekey_precomputed(encrypted, &k_inv)
}

/// Variant of [`rekey`] that takes the precomputed inverse of `k`.
///
/// Scalar inversion is significantly more expensive than scalar multiplication. When the same
/// rekey factor is applied to many ciphertexts (e.g. all blocks of a long value), invert `k`
/// once and use this function per ciphertext.
#[cfg(feature = "elgamal3")]
pub fn rekey_precomputed<G: Group>(
    encrypted: &ElGamal<G>,
    k: &G::Scalar,
    k_inv: &G::Scalar,
) -> ElGamal<G> {
    ElGamal {
        gb: *k_inv * encrypted.gb,
        gc: encrypted.gc,
        gy: *k * encrypted.gy,
    }
}

/// Variant of [`rekey`] that takes the precomputed inverse of `k`.
///
/// Scalar inversion is significantly more expensive than scalar multiplication. When the same
/// rekey factor is applied to many ciphertexts (e.g. all blocks of a long value), invert `k`
/// once and use this function per ciphertext.
#[cfg(not(feature = "elgamal3"))]
pub fn rekey_precomputed<G: Group>(encrypted: &ElGamal<G>, k_inv: &G::Scalar) -> ElGamal<G> {
    ElGamal {
        gb: *k_inv * encrypted.gb,
        gc: encrypted.gc,
    }
}

/// Combination of  [`reshuffle`] and [`rekey`] (more efficient and secure than applying them
/// separately).
pub fn rsk<G: Group>(encrypted: &ElGamal<G>, s: &G::Scalar, k: &G::Scalar) -> ElGamal<G> {
    let ski = *s * G::scalar_inverse(k);
    #[cfg(feature = "elgamal3")]
    return rsk_precomputed(encrypted, s, k, &ski);
    #[cfg(not(feature = "elgamal3"))]
    rsk_precomputed(encrypted, s, &ski)
}

/// Variant of [`rsk`] that takes the precomputed product `ski = s * k^-1`.
///
/// Scalar inversion is significantly more expensive than scalar multiplication. When the same
/// reshuffle and rekey factors are applied to many ciphertexts (e.g. all blocks of a long
/// value), compute `ski` once and use this function per ciphertext.
#[cfg(feature = "elgamal3")]
pub fn rsk_precomputed<G: Group>(
    encrypted: &ElGamal<G>,
    s: &G::Scalar,
    k: &G::Scalar,
    ski: &G::Scalar,
) -> ElGamal<G> {
    ElGamal {
        gb: *ski * encrypted.gb,
        gc: *s * encrypted.gc,
        gy: *k * encrypted.gy,
    }
}

/// Variant of [`rsk`] that takes the precomputed product `ski = s * k^-1`.
///
/// Scalar inversion is significantly more expensive than scalar multiplication. When the same
/// reshuffle and rekey factors are applied to many ciphertexts (e.g. all blocks of a long
/// value), compute `ski` once and use this function per ciphertext.
#[cfg(not(feature = "elgamal3"))]
pub fn rsk_precomputed<G: Group>(
    encrypted: &ElGamal<G>,
    s: &G::Scalar,
    ski: &G::Scalar,
) -> ElGamal<G> {
    ElGamal {
        gb: *ski * encrypted.gb,
        gc: *s * encrypted.gc,
    }
}

/// Combination of [`rerandomize`], [`reshuffle`] and [`rekey`] (more efficient and secure than
/// applying them separately).
#[cfg(feature = "elgamal3")]
pub fn rrsk<G: Group>(m: &ElGamal<G>, r: &G::Scalar, s: &G::Scalar, k: &G::Scalar) -> ElGamal<G> {
    let ski = *s * G::scalar_inverse(k);
    ElGamal {
        gb: ski * m.gb + G::scalar_mult_gen(&(ski * *r)),
        gc: (*s * *r) * m.gy + *s * m.gc,
        gy: *k * m.gy,
    }
}

/// Combination of [`rerandomize`], [`reshuffle`] and [`rekey`] (more efficient and secure than
/// applying them separately).
#[cfg(not(feature = "elgamal3"))]
pub fn rrsk<G: Group>(
    m: &ElGamal<G>,
    gy: &G::Element,
    r: &G::Scalar,
    s: &G::Scalar,
    k: &G::Scalar,
) -> ElGamal<G> {
    let ski = *s * G::scalar_inverse(k);
    ElGamal {
        gb: ski * m.gb + G::scalar_mult_gen(&(ski * *r)),
        gc: (*s * *r) * *gy + *s * m.gc,
    }
}

/// A transitive and reversible n-PEP extension of [`reshuffle`], reshuffling from one pseudonym to
/// another.
pub fn reshuffle2<G: Group>(m: &ElGamal<G>, s_from: &G::Scalar, s_to: &G::Scalar) -> ElGamal<G> {
    let s = G::scalar_inverse(s_from) * *s_to;
    reshuffle(m, &s)
}
/// A transitive and reversible n-PEP extension of [`rekey`], rekeying from one key to
/// another.
pub fn rekey2<G: Group>(m: &ElGamal<G>, k_from: &G::Scalar, k_to: &G::Scalar) -> ElGamal<G> {
    let k = G::scalar_inverse(k_from) * *k_to;
    rekey(m, &k)
}

/// A transitive and reversible n-PEP extension of [`rsk`].
pub fn rsk2<G: Group>(
    m: &ElGamal<G>,
    s_from: &G::Scalar,
    s_to: &G::Scalar,
    k_from: &G::Scalar,
    k_to: &G::Scalar,
) -> ElGamal<G> {
    let s = G::scalar_inverse(s_from) * *s_to;
    let k = G::scalar_inverse(k_from) * *k_to;
    rsk(m, &s, &k)
}

/// A transitive and reversible n-PEP extension of [`rrsk`].
#[cfg(feature = "elgamal3")]
pub fn rrsk2<G: Group>(
    m: &ElGamal<G>,
    r: &G::Scalar,
    s_from: &G::Scalar,
    s_to: &G::Scalar,
    k_from: &G::Scalar,
    k_to: &G::Scalar,
) -> ElGamal<G> {
    let s = G::scalar_inverse(s_from) * *s_to;
    let k = G::scalar_inverse(k_from) * *k_to;
    rrsk(m, r, &s, &k)
}
/// A transitive and reversible n-PEP extension of [`rrsk`].
#[cfg(not(feature = "elgamal3"))]
pub fn rrsk2<G: Group>(
    m: &ElGamal<G>,
    gy: &G::Element,
    r: &G::Scalar,
    s_from: &G::Scalar,
    s_to: &G::Scalar,
    k_from: &G::Scalar,
    k_to: &G::Scalar,
) -> ElGamal<G> {
    let s = G::scalar_inverse(s_from) * *s_to;
    let k = G::scalar_inverse(k_from) * *k_to;
    rrsk(m, gy, r, &s, &k)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::{decrypt, encrypt};

    #[test]
    fn rekey() {
        let mut rng = rand::rng();

        // secret key
        let y = ScalarNonZero::random(&mut rng);
        // public key
        let gy = y * G;

        let k = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt/decrypt this value
        let encrypted = encrypt(&m, &gy, &mut rng);

        let rekeyed = super::rekey(&encrypted, &k);

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&rekeyed, &(k * y)).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&rekeyed, &(k * y));

        assert_eq!(m, decrypted);
    }

    #[test]
    fn reshuffle() {
        let mut rng = rand::rng();

        // secret key
        let y = ScalarNonZero::random(&mut rng);
        // public key
        let gy = y * G;

        let s = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt/decrypt this value
        let encrypted = encrypt(&m, &gy, &mut rng);

        let reshuffled = super::reshuffle(&encrypted, &s);

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&reshuffled, &y).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&reshuffled, &y);

        assert_eq!(s * m, decrypted);
    }

    #[test]
    fn rsk() {
        let mut rng = rand::rng();

        // secret key
        let y = ScalarNonZero::random(&mut rng);
        // public key
        let gy = y * G;

        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt/decrypt this value
        let encrypted = encrypt(&m, &gy, &mut rng);

        let rsked = super::rsk(&encrypted, &s, &k);

        assert_eq!(rsked, super::rekey(&super::reshuffle(&encrypted, &s), &k));

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&rsked, &(k * y)).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&rsked, &(k * y));

        assert_eq!(s * m, decrypted);
    }

    #[test]
    fn rrsk() {
        let mut rng = rand::rng();

        // secret key
        let y = ScalarNonZero::random(&mut rng);
        // public key
        let gy = y * G;

        let r = ScalarNonZero::random(&mut rng);
        let s = ScalarNonZero::random(&mut rng);
        let k = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt/decrypt this value
        let encrypted = encrypt(&m, &gy, &mut rng);

        #[cfg(feature = "elgamal3")]
        let rrsked = super::rrsk(&encrypted, &r, &s, &k);
        #[cfg(not(feature = "elgamal3"))]
        let rrsked = super::rrsk(&encrypted, &gy, &r, &s, &k);

        #[cfg(feature = "elgamal3")]
        assert_eq!(
            rrsked,
            super::rekey(&super::reshuffle(&rerandomize(&encrypted, &r), &s), &k)
        );
        #[cfg(not(feature = "elgamal3"))]
        assert_eq!(
            rrsked,
            super::rekey(&super::reshuffle(&rerandomize(&encrypted, &gy, &r), &s), &k)
        );

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&rrsked, &(k * y)).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&rrsked, &(k * y));

        assert_eq!(s * m, decrypted);
    }

    #[test]
    fn rekey2_from_to() {
        let mut rng = rand::rng();

        // secret key
        let y = ScalarNonZero::random(&mut rng);
        // public key
        let gy = y * G;

        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt/decrypt this value
        let encrypted = encrypt(&m, &(k_from * gy), &mut rng);

        let rekeyed = rekey2(&encrypted, &k_from, &k_to);

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&rekeyed, &(k_to * y)).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&rekeyed, &(k_to * y));

        assert_eq!(m, decrypted);
    }

    #[test]
    fn reshuffle2_from_to() {
        let mut rng = rand::rng();

        // secret key
        let y = ScalarNonZero::random(&mut rng);
        // public key
        let gy = y * G;

        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt/decrypt this value
        let encrypted = encrypt(&m, &gy, &mut rng);

        let reshuffled = reshuffle2(&encrypted, &s_from, &s_to);

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&reshuffled, &y).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&reshuffled, &y);

        assert_eq!(s_from.invert() * s_to * m, decrypted);
    }

    #[test]
    fn rsk2_from_to() {
        let mut rng = rand::rng();

        // secret key
        let y = ScalarNonZero::random(&mut rng);
        // public key
        let gy = y * G;

        let s_from = ScalarNonZero::random(&mut rng);
        let s_to = ScalarNonZero::random(&mut rng);
        let k_from = ScalarNonZero::random(&mut rng);
        let k_to = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt/decrypt this value
        let encrypted = encrypt(&m, &(k_from * gy), &mut rng);

        let rsked = rsk2(&encrypted, &s_from, &s_to, &k_from, &k_to);

        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&rsked, &(k_to * y)).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&rsked, &(k_to * y));

        assert_eq!(s_from.invert() * s_to * m, decrypted);
    }

    #[test]
    fn commutativity() {
        let mut rng = rand::rng();
        // secret key of system
        let sk = ScalarNonZero::random(&mut rng);
        // public key of system
        let pk = sk * G;

        // secret key of user
        let sj = ScalarNonZero::random(&mut rng);
        let yj = sj * sk;
        assert_eq!(yj * G, sj * pk);

        // Lemma 2: RS(RK(..., k), n) == RK(RS(..., n), k)
        let value = GroupElement::random(&mut rng);
        let encrypted = encrypt(&value, &pk, &mut rng);
        let k = ScalarNonZero::random(&mut rng);
        let n = ScalarNonZero::random(&mut rng);
        assert_eq!(
            super::reshuffle(&super::rekey(&encrypted, &k), &n),
            super::rekey(&super::reshuffle(&encrypted, &n), &k)
        );
        assert_eq!(
            super::reshuffle(&super::rekey(&encrypted, &k), &n),
            super::rsk(&encrypted, &n, &k)
        );
    }

    #[test]
    fn reshuffle2_transitivity() {
        let mut rng = rand::rng();

        // secret key
        let y = ScalarNonZero::random(&mut rng);
        // public key
        let gy = y * G;

        // Three users with different shuffle factors
        let s_user1 = ScalarNonZero::random(&mut rng);
        let s_user2 = ScalarNonZero::random(&mut rng);
        let s_user3 = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt value for user1's domain
        let encrypted = encrypt(&(s_user1 * m), &gy, &mut rng);

        // reshuffle from user1 to user2, then from user2 to user3
        let reshuffled_1_to_2 = reshuffle2(&encrypted, &s_user1, &s_user2);
        let reshuffled_2_to_3 = reshuffle2(&reshuffled_1_to_2, &s_user2, &s_user3);

        // reshuffle directly from user1 to user3
        let reshuffled_1_to_3 = reshuffle2(&encrypted, &s_user1, &s_user3);

        // transitivity: going 1->2->3 should equal going 1->3 directly
        assert_eq!(reshuffled_2_to_3, reshuffled_1_to_3);

        // verify decryption gives expected result
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&reshuffled_1_to_3, &y).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&reshuffled_1_to_3, &y);
        assert_eq!(s_user3 * m, decrypted);
    }

    #[test]
    fn rsk2_transitivity() {
        let mut rng = rand::rng();

        // base secret key
        let y = ScalarNonZero::random(&mut rng);
        // base public key
        let gy = y * G;

        // Three users with different shuffle and rekey factors
        let s_user1 = ScalarNonZero::random(&mut rng);
        let s_user2 = ScalarNonZero::random(&mut rng);
        let s_user3 = ScalarNonZero::random(&mut rng);
        let k_user1 = ScalarNonZero::random(&mut rng);
        let k_user2 = ScalarNonZero::random(&mut rng);
        let k_user3 = ScalarNonZero::random(&mut rng);

        // choose a random value to encrypt
        let m = GroupElement::random(&mut rng);

        // encrypt value for user1's domain and key
        let encrypted = encrypt(&(s_user1 * m), &(k_user1 * gy), &mut rng);

        // rsk from user1 to user2, then from user2 to user3
        let rsked_1_to_2 = rsk2(&encrypted, &s_user1, &s_user2, &k_user1, &k_user2);
        let rsked_2_to_3 = rsk2(&rsked_1_to_2, &s_user2, &s_user3, &k_user2, &k_user3);

        // rsk directly from user1 to user3
        let rsked_1_to_3 = rsk2(&encrypted, &s_user1, &s_user3, &k_user1, &k_user3);

        // transitivity: going 1->2->3 should equal going 1->3 directly
        assert_eq!(rsked_2_to_3, rsked_1_to_3);

        // verify decryption with user3's key gives expected result
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&rsked_1_to_3, &(k_user3 * y)).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&rsked_1_to_3, &(k_user3 * y));
        assert_eq!(s_user3 * m, decrypted);
    }
}
