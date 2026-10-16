//! Discrete-logarithm-equivalence (DLEQ) proofs in the encoding of RFC 9497.
//!
//! A DLEQ proof shows that the same secret scalar `k` relates two pairs of group elements,
//! `B = k * A` and `D_i = k * C_i`, without revealing `k`. This module implements the
//! `GenerateProof` / `VerifyProof` pair of [RFC 9497, Section 2.2], including the
//! `ComputeComposites` batching that lets a single proof cover many `(C_i, D_i)` pairs
//! transformed with the same scalar.
//!
//! # Relation to [`super::zkps`]
//!
//! [`super::zkps::Proof`] is the four-element encoding `(N, C1, C2, s)` of the published paper.
//! It remains available and unchanged. The encoding here is the RFC's: a proof is the two
//! scalars `(c, s)` and the verifier recomputes the commitments. Proofs in the two encodings are
//! **not** interchangeable.
//!
//! # Domain separation
//!
//! The transcripts end in the bare labels `"Composite"` and `"Challenge"`, and the context
//! string enters through the DSTs of `HashToScalar` (`"HashToScalar-" || contextString`) and of
//! the seed (`"Seed-" || contextString`), exactly as in the RFC. The context string comes from
//! the group's ciphersuite,
//! [`Group::CIPHERSUITE`](crate::elgamal::arithmetic::Group::CIPHERSUITE), so two deployments
//! with different context strings produce proofs that never verify against one another.
//!
//! The implementation is cross-checked against the ristretto255-SHA512 VOPRF test vectors of
//! RFC 9497 Appendix A.1.2, for both a single pair and a batch of two.
//!
//! # Example
//!
//! ```
//! # use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
//! # use libpep::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
//! # use libpep::elgamal::dleq::{generate_proof, verify_proof};
//! let mut rng = rand::rng();
//!
//! let k = ScalarNonZero::random(&mut rng);
//! let a = G;
//! let b = k * a;
//! let cs = [GroupElement::random(&mut rng), GroupElement::random(&mut rng)];
//! let ds = [k * cs[0], k * cs[1]];
//!
//! let proof = generate_proof(&k, &a, &b, &cs, &ds, &mut rng).unwrap();
//! assert!(verify_proof(&a, &b, &cs, &ds, &proof));
//! ```
//!
//! [RFC 9497, Section 2.2]: https://www.rfc-editor.org/rfc/rfc9497.html#section-2.2

pub mod generic;

pub use generic::ProofError;

use crate::elgamal::arithmetic::group_elements::GroupElement;
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use crate::elgamal::arithmetic::Ristretto255;
use rand_core::{CryptoRng, Rng};

/// The [`Proof`](generic::Proof) over ristretto255.
pub type Proof = generic::Proof<Ristretto255>;

/// Byte length of a serialized proof: two scalars.
pub const PROOF_SIZE: usize = Proof::LENGTH;

/// `GenerateProof` of RFC 9497, Section 2.2; see [`generic::generate_proof`].
///
/// # Errors
///
/// Returns [`ProofError::MismatchedLists`] if `cs` and `ds` differ in length or are empty.
pub fn generate_proof<R: Rng + CryptoRng>(
    k: &ScalarNonZero,
    a: &GroupElement,
    b: &GroupElement,
    cs: &[GroupElement],
    ds: &[GroupElement],
    rng: &mut R,
) -> Result<Proof, ProofError> {
    generic::generate_proof::<Ristretto255, R>(k, a, b, cs, ds, rng)
}

/// `VerifyProof` of RFC 9497, Section 2.2; see [`generic::verify_proof`].
#[must_use]
pub fn verify_proof(
    a: &GroupElement,
    b: &GroupElement,
    cs: &[GroupElement],
    ds: &[GroupElement],
    proof: &Proof,
) -> bool {
    generic::verify_proof::<Ristretto255>(a, b, cs, ds, proof)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::generic::{generate_proof_with, verify_proof_with, Dsts};
    use super::*;
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::elgamal::arithmetic::Group;

    #[test]
    fn single_pair_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], rng).unwrap();
        assert!(verify_proof(&G, &(k * G), &[c], &[k * c], &proof));
    }

    #[test]
    fn batched_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let cs: Vec<_> = (0..3).map(|_| GroupElement::random(rng)).collect();
        let ds: Vec<_> = cs.iter().map(|c| k * *c).collect();
        let proof = generate_proof(&k, &G, &(k * G), &cs, &ds, rng).unwrap();
        assert!(verify_proof(&G, &(k * G), &cs, &ds, &proof));
    }

    /// A batched proof must not verify if any single `d_i` is replaced.
    #[test]
    fn batched_proof_rejects_a_single_tampered_element() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let cs: Vec<_> = (0..3).map(|_| GroupElement::random(rng)).collect();
        let ds: Vec<_> = cs.iter().map(|c| k * *c).collect();
        let proof = generate_proof(&k, &G, &(k * G), &cs, &ds, rng).unwrap();

        for i in 0..ds.len() {
            let mut tampered = ds.clone();
            tampered[i] = GroupElement::random(rng);
            assert!(
                !verify_proof(&G, &(k * G), &cs, &tampered, &proof),
                "tampering with d_{i} was not detected"
            );
        }
    }

    #[test]
    fn wrong_scalar_does_not_verify() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let other = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], rng).unwrap();
        assert!(!verify_proof(&G, &(other * G), &[c], &[k * c], &proof));
    }

    /// The context string is part of the challenge, so proofs do not cross ciphersuites.
    #[test]
    fn proofs_are_ciphersuite_separated() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        // A different ciphersuite identifier gives a different context string, so the challenge
        // differs and a proof made under one does not verify under the other.
        let ours = Dsts::from_ciphersuite(&Ristretto255::CIPHERSUITE);
        let other = Dsts::from_ciphersuite(&crate::ciphersuite!("other-suite"));
        let r = ScalarNonZero::random(rng);
        let proof =
            generate_proof_with::<Ristretto255>(&k, &G, &(k * G), &[c], &[k * c], &ours, &r);
        assert!(verify_proof(&G, &(k * G), &[c], &[k * c], &proof));
        assert!(!verify_proof_with::<Ristretto255>(
            &G,
            &(k * G),
            &[c],
            &[k * c],
            &proof,
            &other
        ));
    }

    #[test]
    fn mismatched_lists_are_rejected() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        assert_eq!(
            generate_proof(&k, &G, &(k * G), &[c], &[], rng).unwrap_err(),
            ProofError::MismatchedLists { cs: 1, ds: 0 }
        );
        assert_eq!(
            generate_proof(&k, &G, &(k * G), &[], &[], rng).unwrap_err(),
            ProofError::MismatchedLists { cs: 0, ds: 0 }
        );
    }

    /// The DSTs of RFC 9497's own VOPRF ciphersuite, whose context string is
    /// `"OPRFV1-" || I2OSP(modeVOPRF, 1) || "-" || "ristretto255-SHA512"` with modeVOPRF = 0x01.
    ///
    /// This is deliberately NOT our [`Ciphersuite`](crate::elgamal::arithmetic::Ciphersuite): the draft uses the prefix `"coPRFV1-"` so that
    /// pseudonyms of the two protocols are domain separated on the same group. Reproducing the
    /// RFC's vectors therefore requires the RFC's own context string.
    fn rfc9497_voprf_dsts() -> Dsts {
        let mut ctx = b"OPRFV1-".to_vec();
        ctx.push(0x01);
        ctx.push(b'-');
        ctx.extend_from_slice(b"ristretto255-SHA512");
        let with = |label: &[u8]| {
            let mut d = label.to_vec();
            d.extend_from_slice(&ctx);
            d
        };
        Dsts {
            seed: with(b"Seed-"),
            hash_to_scalar: with(b"HashToScalar-"),
        }
    }

    fn element(hex_str: &str) -> GroupElement {
        GroupElement::from_slice(&hex::decode(hex_str).unwrap()).unwrap()
    }

    fn scalar(hex_str: &str) -> ScalarNonZero {
        ScalarNonZero::from_slice(&hex::decode(hex_str).unwrap()).unwrap()
    }

    /// Cross-check `GenerateProof` against RFC 9497 Appendix A.1.2, Test Vector 1 (batch size 1).
    ///
    /// With `a = G`, `b = pkSm`, `cs = [BlindedElement]`, `ds = [EvaluationElement]` and the
    /// vector's fixed `ProofRandomScalar`, the produced proof bytes must equal the vector's.
    #[test]
    fn rfc9497_appendix_a_1_2_single() {
        let dsts = rfc9497_voprf_dsts();
        let sk = scalar("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909");
        let pk = element("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e");
        let blinded = element("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945");
        let evaluated = element("aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e");
        let r = scalar("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e");
        let expected = "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd06\
                        6d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d";

        // The vector's key material must be self-consistent for the rest to mean anything.
        assert_eq!(sk * G, pk, "pkSm is not skSm * G");
        assert_eq!(
            sk * blinded,
            evaluated,
            "EvaluationElement is not skSm * BlindedElement"
        );

        let proof =
            generate_proof_with::<Ristretto255>(&sk, &G, &pk, &[blinded], &[evaluated], &dsts, &r);
        assert_eq!(hex::encode(proof.to_bytes()), expected);
        assert!(verify_proof_with::<Ristretto255>(
            &G,
            &pk,
            &[blinded],
            &[evaluated],
            &proof,
            &dsts
        ));
    }

    /// The same cross-check for Test Vector 3 (batch size 2), which exercises
    /// `ComputeComposites` over more than one pair.
    #[test]
    fn rfc9497_appendix_a_1_2_batched() {
        let dsts = rfc9497_voprf_dsts();
        let sk = scalar("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909");
        let pk = element("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e");
        let blinded = [
            element("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"),
            element("90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654"),
        ];
        let evaluated = [
            element("aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"),
            element("cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a"),
        ];
        let r = scalar("419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c");
        let expected = "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a\
                        5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08";

        let proof =
            generate_proof_with::<Ristretto255>(&sk, &G, &pk, &blinded, &evaluated, &dsts, &r);
        assert_eq!(hex::encode(proof.to_bytes()), expected);
        assert!(verify_proof_with::<Ristretto255>(
            &G, &pk, &blinded, &evaluated, &proof, &dsts
        ));

        // And the batched proof must still be sensitive to each element.
        for i in 0..evaluated.len() {
            let mut tampered = evaluated;
            tampered[i] = G;
            assert!(!verify_proof_with::<Ristretto255>(
                &G, &pk, &blinded, &tampered, &proof, &dsts
            ));
        }
    }

    #[test]
    fn proof_serialization_round_trip() {
        let rng = &mut rand::rng();
        let k = ScalarNonZero::random(rng);
        let c = GroupElement::random(rng);
        let proof = generate_proof(&k, &G, &(k * G), &[c], &[k * c], rng).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), PROOF_SIZE);
        assert_eq!(Proof::from_slice(&bytes).unwrap(), proof);
        assert!(Proof::from_slice(&bytes[..63]).is_none());
    }
}
