//! PEP primitives for [rekey]ing, [reshuffle]ing, [rerandomize]ation of [ElGamal] ciphertexts, their
//! transitive and reversible n-PEP extensions, and combined versions.
#[cfg(not(feature = "elgamal3"))]
use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::group_elements::G;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::base::elgamal::*;

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arithmetic::group_elements::GroupElement;
    use crate::base::elgamal::{decrypt, encrypt};

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

        let rekeyed = super::rekey2(&encrypted, &k_from, &k_to);

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

        let reshuffled = super::reshuffle2(&encrypted, &s_from, &s_to);

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

        let rsked = super::rsk2(&encrypted, &s_from, &s_to, &k_from, &k_to);

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
        let reshuffled_1_to_2 = super::reshuffle2(&encrypted, &s_user1, &s_user2);
        let reshuffled_2_to_3 = super::reshuffle2(&reshuffled_1_to_2, &s_user2, &s_user3);

        // reshuffle directly from user1 to user3
        let reshuffled_1_to_3 = super::reshuffle2(&encrypted, &s_user1, &s_user3);

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
        let rsked_1_to_2 = super::rsk2(&encrypted, &s_user1, &s_user2, &k_user1, &k_user2);
        let rsked_2_to_3 = super::rsk2(&rsked_1_to_2, &s_user2, &s_user3, &k_user2, &k_user3);

        // rsk directly from user1 to user3
        let rsked_1_to_3 = super::rsk2(&encrypted, &s_user1, &s_user3, &k_user1, &k_user3);

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
