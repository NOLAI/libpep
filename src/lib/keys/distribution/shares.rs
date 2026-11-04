//! Session key shares for distributed transcryptors.
//!
//! A session key share is one transcryptor's contribution to a session key. Combining all shares
//! with the corresponding [blinded global secret key](super::blinding) yields the session key;
//! a single share reveals nothing about it on its own.
//!
//! Shares are protocol material, not keys: no data is encrypted towards them and they have no
//! associated public key, so they do not implement [`SecretKey`].

use super::blinding::{
    BlindedAttributeGlobalSecretKey, BlindedGlobalSecretKey, BlindedPseudonymGlobalSecretKey,
    BlindingFactor,
};
#[cfg(feature = "verifiable")]
use crate::ciphersuite::Ciphersuite;
#[cfg(feature = "verifiable")]
use crate::ciphersuite::Ristretto255Sha512;
#[cfg(feature = "verifiable")]
use crate::elgamal::verifiable::RekeyFactorCommitment;
use crate::factors::types::{AttributeRekeyFactor, Factor, PseudonymRekeyFactor};
use crate::group::decode_hex;
use crate::group::Group;
use crate::group::Ristretto255;
#[cfg(feature = "verifiable")]
use crate::keys::distribution::proofs::{BlindingCommitment, SessionKeyShareProof};
use crate::keys::traits::SecretKey;
use crate::keys::types::{AttributeSessionSecretKey, PseudonymSessionSecretKey};
#[cfg(feature = "verifiable")]
use rand_core::{CryptoRng, Rng};

/// One transcryptor's contribution to a session key.
///
/// The associated types tie a share to the rekey factor it is made from, the blinded global
/// secret key it is combined with, and the session secret key that combination yields.
pub trait SessionKeyShare: Sized {
    /// The group the share is a scalar of.
    type Group: Group;
    /// The rekey factor this share is made from.
    type Factor: Factor<Group = Self::Group>;
    /// The blinded global secret key this share is combined with.
    type BlindedGlobalSecretKey: BlindedGlobalSecretKey<Group = Self::Group>;
    /// The session secret key that combining the shares yields.
    type SessionSecretKey: SecretKey<Group = Self::Group>;

    /// The scalar value of this share.
    fn value(&self) -> &<Self::Group as Group>::Scalar;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: <Self::Group as Group>::Scalar) -> Self;

    /// Create a share from a rekey factor and this transcryptor's blinding factor.
    ///
    /// The share is the product of the two, so that the blinding factors cancel out against the
    /// blinded global secret key when the shares are combined.
    fn from_rekey_factor(
        rekey_factor: &Self::Factor,
        blinding_factor: &BlindingFactor<Self::Group>,
    ) -> Self {
        Self::from_scalar(rekey_factor.scalar() * *blinding_factor.value())
    }

    /// Encode as a byte array.
    fn to_bytes(&self) -> <Self::Group as Group>::ScalarBytes {
        Self::Group::serialize_scalar(self.value())
    }

    /// Encode as a hexadecimal string.
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a byte array.
    fn from_bytes(bytes: &<Self::Group as Group>::ScalarBytes) -> Option<Self> {
        Self::from_slice(bytes.as_ref())
    }

    /// Decode from a slice of bytes.
    fn from_slice(slice: &[u8]) -> Option<Self> {
        Self::Group::deserialize_scalar(slice).map(Self::from_scalar)
    }

    /// Decode from a hexadecimal string.
    fn from_hex(s: &str) -> Option<Self> {
        decode_hex::<<Self::Group as Group>::ScalarBytes>(s)
            .and_then(|b| Self::from_slice(b.as_ref()))
    }
}

/// A pseudonym session key share, which is a part of a pseudonym session key provided by one transcryptor.
/// By combining all pseudonym session key shares and the [`BlindedPseudonymGlobalSecretKey`], a pseudonym session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, zeroize::Zeroize, derive_more::Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
#[zeroize(bound = "")]
#[debug("PseudonymSessionKeyShare([redacted])")]
pub struct PseudonymSessionKeyShare<G: Group = Ristretto255>(pub(crate) G::Scalar);

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`BlindedAttributeGlobalSecretKey`], an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq, zeroize::Zeroize, derive_more::Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
#[zeroize(bound = "")]
#[debug("AttributeSessionKeyShare([redacted])")]
pub struct AttributeSessionKeyShare<G: Group = Ristretto255>(pub(crate) G::Scalar);

macro_rules! impl_session_key_share {
    ($($t:ident { rekey: $rf:ident, blinded: $b:ident, session: $sk:ident }),+ $(,)?) => {$(
        impl<G: Group> SessionKeyShare for $t<G> {
            type Group = G;
            type Factor = $rf<G>;
            type BlindedGlobalSecretKey = $b<G>;
            type SessionSecretKey = $sk<G>;

            fn value(&self) -> &G::Scalar {
                &self.0
            }
            fn from_scalar(scalar: G::Scalar) -> Self {
                Self(scalar)
            }
        }
    )+};
}

impl_session_key_share!(
    PseudonymSessionKeyShare {
        rekey: PseudonymRekeyFactor,
        blinded: BlindedPseudonymGlobalSecretKey,
        session: PseudonymSessionSecretKey
    },
    AttributeSessionKeyShare {
        rekey: AttributeRekeyFactor,
        blinded: BlindedAttributeGlobalSecretKey,
        session: AttributeSessionSecretKey
    },
);

/// A pair of session key shares containing both pseudonym and attribute shares.
#[derive(Copy, Clone, Eq, PartialEq, Debug, zeroize::Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
#[zeroize(bound = "")]
pub struct SessionKeyShares<G: Group = Ristretto255> {
    /// The share of the pseudonym session key.
    pub pseudonym: PseudonymSessionKeyShare<G>,
    /// The share of the attribute session key.
    pub attribute: AttributeSessionKeyShare<G>,
}

/// Create a session key share from a rekey factor and blinding factor.
/// Works for both pseudonym and attribute key shares, depending on the types.
pub fn make_session_key_share<S: SessionKeyShare>(
    rekey_factor: &S::Factor,
    blinding_factor: &BlindingFactor<S::Group>,
) -> S {
    S::from_rekey_factor(rekey_factor, blinding_factor)
}

/// Create a [`PseudonymSessionKeyShare`] from a [`PseudonymRekeyFactor`] and a [`BlindingFactor`].
pub fn make_pseudonym_session_key_share<G: Group>(
    rekey_factor: &PseudonymRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
) -> PseudonymSessionKeyShare<G> {
    make_session_key_share(rekey_factor, blinding_factor)
}

/// Create an [`AttributeSessionKeyShare`] from an [`AttributeRekeyFactor`] and a [`BlindingFactor`].
pub fn make_attribute_session_key_share<G: Group>(
    rekey_factor: &AttributeRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
) -> AttributeSessionKeyShare<G> {
    make_session_key_share(rekey_factor, blinding_factor)
}

/// Create [`SessionKeyShares`] (both pseudonym and attribute) from rekey factors and a blinding factor.
pub fn make_session_key_shares<G: Group>(
    pseudonym_rekey_factor: &PseudonymRekeyFactor<G>,
    attribute_rekey_factor: &AttributeRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
) -> SessionKeyShares<G> {
    SessionKeyShares {
        pseudonym: make_pseudonym_session_key_share(pseudonym_rekey_factor, blinding_factor),
        attribute: make_attribute_session_key_share(attribute_rekey_factor, blinding_factor),
    }
}

/// Why a session key share with a proof was refused.
#[cfg(feature = "verifiable")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionKeyShareError {
    /// The blinding factor is 1: its commitment equals `G` and the share `u_i = k_i` is the
    /// rekey factor in the clear. Generate a fresh blinding factor (for example with
    /// [`BlindingFactor::random`], which excludes 1).
    #[error("blinding factor must not be 1")]
    WeakBlinding,
}

/// The proofs of both session key shares of a transcryptor.
#[cfg(feature = "verifiable")]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct SessionKeyShareProofs<G: Group = Ristretto255> {
    /// The proof of the pseudonym session key share.
    pub pseudonym: SessionKeyShareProof<G>,
    /// The proof of the attribute session key share.
    pub attribute: SessionKeyShareProof<G>,
}

/// A session key share `u_i = b_i · k_i` with the proof `ZKP{U_i = b_i · K_i}` that it was made
/// from the committed blinding factor and rekey factor. The user
/// receiving the share checks it with
/// [`SessionKeyShareProof::verify_share`].
#[cfg(feature = "verifiable")]
pub fn make_session_key_share_with_proof<
    S: SessionKeyShare,
    C: Ciphersuite<Group = S::Group>,
    R: Rng + CryptoRng,
>(
    rekey_factor: &S::Factor,
    blinding_factor: &BlindingFactor<S::Group>,
    rng: &mut R,
) -> Result<(S, SessionKeyShareProof<S::Group>), SessionKeyShareError> {
    if *blinding_factor.value() == <S::Group as Group>::scalar_one() {
        return Err(SessionKeyShareError::WeakBlinding);
    }
    let share = S::from_rekey_factor(rekey_factor, blinding_factor);
    let rekey_commitment = RekeyFactorCommitment::<S::Group>::new(&rekey_factor.scalar());
    let proof =
        SessionKeyShareProof::new::<C, R>(blinding_factor.value(), &rekey_commitment.point(), rng);
    Ok((share, proof))
}

/// A [`PseudonymSessionKeyShare`] with its proof; see [`make_session_key_share_with_proof`].
#[cfg(feature = "verifiable")]
#[allow(clippy::type_complexity)]
pub fn make_pseudonym_session_key_share_with_proof_generic<C: Ciphersuite, R: Rng + CryptoRng>(
    rekey_factor: &PseudonymRekeyFactor<C::Group>,
    blinding_factor: &BlindingFactor<C::Group>,
    rng: &mut R,
) -> Result<
    (
        PseudonymSessionKeyShare<C::Group>,
        SessionKeyShareProof<C::Group>,
    ),
    SessionKeyShareError,
> {
    make_session_key_share_with_proof::<_, C, R>(rekey_factor, blinding_factor, rng)
}

/// [`make_pseudonym_session_key_share_with_proof_generic`] for ristretto255 with SHA-512.
#[cfg(feature = "verifiable")]
#[allow(clippy::type_complexity)]
pub fn make_pseudonym_session_key_share_with_proof<R: Rng + CryptoRng>(
    rekey_factor: &PseudonymRekeyFactor,
    blinding_factor: &BlindingFactor,
    rng: &mut R,
) -> Result<(PseudonymSessionKeyShare, SessionKeyShareProof), SessionKeyShareError> {
    make_pseudonym_session_key_share_with_proof_generic::<Ristretto255Sha512, R>(
        rekey_factor,
        blinding_factor,
        rng,
    )
}

/// An [`AttributeSessionKeyShare`] with its proof; see [`make_session_key_share_with_proof`].
#[cfg(feature = "verifiable")]
#[allow(clippy::type_complexity)]
pub fn make_attribute_session_key_share_with_proof_generic<C: Ciphersuite, R: Rng + CryptoRng>(
    rekey_factor: &AttributeRekeyFactor<C::Group>,
    blinding_factor: &BlindingFactor<C::Group>,
    rng: &mut R,
) -> Result<
    (
        AttributeSessionKeyShare<C::Group>,
        SessionKeyShareProof<C::Group>,
    ),
    SessionKeyShareError,
> {
    make_session_key_share_with_proof::<_, C, R>(rekey_factor, blinding_factor, rng)
}

/// [`make_attribute_session_key_share_with_proof_generic`] for ristretto255 with SHA-512.
#[cfg(feature = "verifiable")]
#[allow(clippy::type_complexity)]
pub fn make_attribute_session_key_share_with_proof<R: Rng + CryptoRng>(
    rekey_factor: &AttributeRekeyFactor,
    blinding_factor: &BlindingFactor,
    rng: &mut R,
) -> Result<(AttributeSessionKeyShare, SessionKeyShareProof), SessionKeyShareError> {
    make_attribute_session_key_share_with_proof_generic::<Ristretto255Sha512, R>(
        rekey_factor,
        blinding_factor,
        rng,
    )
}

/// Both session key shares with their proofs; see [`make_session_key_share_with_proof`].
#[cfg(feature = "verifiable")]
#[allow(clippy::type_complexity)]
pub fn make_session_key_shares_with_proof_generic<C: Ciphersuite, R: Rng + CryptoRng>(
    pseudonym_rekey_factor: &PseudonymRekeyFactor<C::Group>,
    attribute_rekey_factor: &AttributeRekeyFactor<C::Group>,
    blinding_factor: &BlindingFactor<C::Group>,
    rng: &mut R,
) -> Result<(SessionKeyShares<C::Group>, SessionKeyShareProofs<C::Group>), SessionKeyShareError> {
    let (pseudonym, pseudonym_proof) = make_pseudonym_session_key_share_with_proof_generic::<C, R>(
        pseudonym_rekey_factor,
        blinding_factor,
        rng,
    )?;
    let (attribute, attribute_proof) = make_attribute_session_key_share_with_proof_generic::<C, R>(
        attribute_rekey_factor,
        blinding_factor,
        rng,
    )?;
    Ok((
        SessionKeyShares {
            pseudonym,
            attribute,
        },
        SessionKeyShareProofs {
            pseudonym: pseudonym_proof,
            attribute: attribute_proof,
        },
    ))
}

/// [`make_session_key_shares_with_proof_generic`] for ristretto255 with SHA-512.
#[cfg(feature = "verifiable")]
#[allow(clippy::type_complexity)]
pub fn make_session_key_shares_with_proof<R: Rng + CryptoRng>(
    pseudonym_rekey_factor: &PseudonymRekeyFactor,
    attribute_rekey_factor: &AttributeRekeyFactor,
    blinding_factor: &BlindingFactor,
    rng: &mut R,
) -> Result<(SessionKeyShares, SessionKeyShareProofs), SessionKeyShareError> {
    make_session_key_shares_with_proof_generic::<Ristretto255Sha512, R>(
        pseudonym_rekey_factor,
        attribute_rekey_factor,
        blinding_factor,
        rng,
    )
}

#[cfg(feature = "verifiable")]
impl<G: Group> SessionKeyShareProof<G> {
    /// Verify the proof and bind it to the share scalar actually received.
    ///
    /// This is the check a user of a session key share must perform. It
    /// has two parts:
    ///
    /// 1. the ZKP is valid against the preconfigured `B_i = b_i · G` and the
    ///    rekey commitment `K_i`, so the proven `U_i` equals `b_i · K_i`
    ///    ([`SessionKeyShareProof::verify`]); and
    /// 2. `U_i == u_i · G` for the share scalar `u_i` that was received, so the
    ///    scalar the user is about to fold into its session key is the one the
    ///    proof is about.
    ///
    /// Without the second check a transcryptor can hand over a perfectly valid
    /// proof together with an unrelated scalar: the proof verifies, the share
    /// is wrong, and the resulting session key silently decrypts to nothing
    /// usable. Prefer this method over [`SessionKeyShareProof::verify`].
    ///
    /// # Arguments
    ///
    /// * `share` - the session key share scalar `u_i` that was received
    /// * `blinding_commitment` - B_i = b_i * G (preconfigured commitment)
    /// * `rekey_commitment` - K_i = k_i * G (from factor commitments)
    ///
    /// # Returns
    ///
    /// `true` only if the proof verifies and the share matches it.
    pub fn verify_share<C: Ciphersuite<Group = G>, S: SessionKeyShare<Group = G>>(
        &self,
        share: &S,
        blinding_commitment: &BlindingCommitment<G>,
        rekey_commitment: &G::Element,
    ) -> bool {
        self.verify::<C>(blinding_commitment, rekey_commitment) && self.matches_share(share)
    }

    /// Whether `U_i == u_i · G` for the given share scalar.
    ///
    /// This is only the binding half of the check; on its own it says nothing
    /// about whether the proof is valid. Use [`SessionKeyShareProof::verify_share`]
    /// unless the proof has already been verified separately.
    ///
    /// Both sides are public group elements (`U_i` is published by the
    /// transcryptor and `u_i · G` is derived from it), so an ordinary equality
    /// comparison is appropriate here; the secret scalar itself is never
    /// compared.
    pub fn matches_share<S: SessionKeyShare<Group = G>>(&self, share: &S) -> bool {
        *share.value() * G::generator() == *self.share_commitment()
    }
}

#[cfg(all(test, feature = "verifiable"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proof_tests {
    use super::*;
    use crate::ciphersuite::Ristretto255Sha512;
    use crate::contexts::EncryptionContext;
    use crate::factors::{
        make_attribute_rekey_factor, make_pseudonym_rekey_factor, Factor, RekeyingSecret,
    };
    use crate::group::elements::G;
    use crate::group::scalars::ScalarNonZero;
    use crate::group::Ristretto255;
    use crate::keys::distribution::BlindingFactor;

    type C = Ristretto255Sha512;
    type BlindingCommitment = crate::keys::distribution::BlindingCommitment<Ristretto255>;
    type SessionKeyShareProof = super::SessionKeyShareProof<Ristretto255>;
    type PseudonymSessionKeyShare = super::PseudonymSessionKeyShare<Ristretto255>;
    type AttributeSessionKeyShare = super::AttributeSessionKeyShare<Ristretto255>;

    #[test]
    fn shares_with_proof_verify() {
        let mut rng = rand::rng();
        let session = EncryptionContext::from("test-context");
        let secret = RekeyingSecret::from(b"test-secret".to_vec());
        let blinding = BlindingFactor::<Ristretto255>::random(&mut rng);
        let commitment = BlindingCommitment::new(blinding.value());
        assert_eq!(*commitment.value(), *blinding.value() * G);

        let k = make_pseudonym_rekey_factor(&secret, &session);
        let (share, proof) =
            make_pseudonym_session_key_share_with_proof_generic::<C, _>(&k, &blinding, &mut rng)
                .unwrap();
        let k_commitment = RekeyFactorCommitment::<Ristretto255>::new(&k.scalar()).point();
        assert!(proof.verify_share::<C, _>(&share, &commitment, &k_commitment));

        let k = make_attribute_rekey_factor(&secret, &session);
        let (share, proof) =
            make_attribute_session_key_share_with_proof_generic::<C, _>(&k, &blinding, &mut rng)
                .unwrap();
        let k_commitment = RekeyFactorCommitment::<Ristretto255>::new(&k.scalar()).point();
        assert!(proof.verify_share::<C, _>(&share, &commitment, &k_commitment));
    }

    #[test]
    fn shares_with_proof_reject_unit_blinding() {
        let mut rng = rand::rng();
        let k = make_pseudonym_rekey_factor(
            &RekeyingSecret::from(b"test-secret".to_vec()),
            &EncryptionContext::from("test-context"),
        );
        let blinding = BlindingFactor::<Ristretto255>::from_scalar(ScalarNonZero::one());
        assert_eq!(
            make_pseudonym_session_key_share_with_proof_generic::<C, _>(&k, &blinding, &mut rng)
                .err(),
            Some(SessionKeyShareError::WeakBlinding)
        );
    }

    #[test]
    fn verify_share_accepts_the_matching_share() {
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;
        let proof = SessionKeyShareProof::new::<C, _>(&blinding, &rekey_commitment, &mut rng);

        // The honest share: u_i = b_i * k_i.
        let share = PseudonymSessionKeyShare::from_scalar(blinding * rekey_factor);

        assert!(proof.verify_share::<C, _>(&share, &blinding_commitment, &rekey_commitment));
    }

    #[test]
    fn verify_share_rejects_a_share_that_does_not_match_a_valid_proof() {
        // The proof here is entirely valid: it verifies against the right
        // commitments. Only the scalar handed over alongside it is wrong,
        // which is the attack `verify` alone cannot catch.
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;
        let proof = SessionKeyShareProof::new::<C, _>(&blinding, &rekey_commitment, &mut rng);

        // The proof itself is sound...
        assert!(proof.verify::<C>(&blinding_commitment, &rekey_commitment));

        // ...but the share does not correspond to it.
        let wrong_share = PseudonymSessionKeyShare::from_scalar(ScalarNonZero::random(&mut rng));

        assert!(!proof.matches_share(&wrong_share));
        assert!(!proof.verify_share::<C, _>(&wrong_share, &blinding_commitment, &rekey_commitment));
    }

    #[test]
    fn verify_share_rejects_a_matching_share_under_a_bad_proof() {
        // Mirror image: the share matches `U_i`, but the proof does not verify
        // against the configured blinding commitment.
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let wrong_blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let wrong_commitment = BlindingCommitment::new(&wrong_blinding);
        let rekey_commitment = rekey_factor * G;
        let proof = SessionKeyShareProof::new::<C, _>(&blinding, &rekey_commitment, &mut rng);

        let share = PseudonymSessionKeyShare::from_scalar(blinding * rekey_factor);

        assert!(proof.matches_share(&share));
        assert!(!proof.verify_share::<C, _>(&share, &wrong_commitment, &rekey_commitment));
    }

    #[test]
    fn verify_share_works_for_attribute_shares_too() {
        let mut rng = rand::rng();
        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;
        let proof = SessionKeyShareProof::new::<C, _>(&blinding, &rekey_commitment, &mut rng);

        let share = AttributeSessionKeyShare::from_scalar(blinding * rekey_factor);
        let wrong = AttributeSessionKeyShare::from_scalar(ScalarNonZero::random(&mut rng));

        assert!(proof.verify_share::<C, _>(&share, &blinding_commitment, &rekey_commitment));
        assert!(!proof.verify_share::<C, _>(&wrong, &blinding_commitment, &rekey_commitment));
    }

    #[test]
    fn test_session_key_share_proof_wrong_blinding() {
        let mut rng = rand::rng();

        let blinding = ScalarNonZero::random(&mut rng);
        let wrong_blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);

        let wrong_commitment = BlindingCommitment::new(&wrong_blinding);
        let rekey_commitment = rekey_factor * G;

        let proof = SessionKeyShareProof::new::<C, _>(&blinding, &rekey_commitment, &mut rng);

        // Should fail with wrong blinding commitment
        assert!(!proof.verify::<C>(&wrong_commitment, &rekey_commitment));
    }

    #[test]
    fn test_session_key_share_proof_wrong_rekey() {
        let mut rng = rand::rng();

        let blinding = ScalarNonZero::random(&mut rng);
        let rekey_factor = ScalarNonZero::random(&mut rng);
        let wrong_rekey_factor = ScalarNonZero::random(&mut rng);

        let blinding_commitment = BlindingCommitment::new(&blinding);
        let rekey_commitment = rekey_factor * G;
        let wrong_rekey_commitment = wrong_rekey_factor * G;

        let proof = SessionKeyShareProof::new::<C, _>(&blinding, &rekey_commitment, &mut rng);

        // Should fail with wrong rekey commitment
        assert!(!proof.verify::<C>(&blinding_commitment, &wrong_rekey_commitment));
    }
}
