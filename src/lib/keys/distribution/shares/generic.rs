//! Session key shares generic over the [`Group`].

use super::super::blinding::generic::{
    BlindedAttributeGlobalSecretKey, BlindedGlobalSecretKey, BlindedPseudonymGlobalSecretKey,
    BlindingFactor,
};
use crate::elgamal::arithmetic::group::decode_hex;
use crate::elgamal::arithmetic::group::Group;
#[cfg(feature = "verifiable")]
use crate::elgamal::verifiable::generic::RekeyFactorCommitment;
use crate::factors::types::generic::{AttributeRekeyFactor, Factor, PseudonymRekeyFactor};
#[cfg(feature = "verifiable")]
use crate::keys::distribution::proofs::generic::SessionKeyShareProof;
use crate::keys::traits::SecretKey;
use crate::keys::types::generic::{AttributeSessionSecretKey, PseudonymSessionSecretKey};
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
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct PseudonymSessionKeyShare<G: Group>(pub(crate) G::Scalar);

/// An attribute session key share, which is a part of an attribute session key provided by one transcryptor.
/// By combining all attribute session key shares and the [`BlindedAttributeGlobalSecretKey`], an attribute session key can be derived.
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct AttributeSessionKeyShare<G: Group>(pub(crate) G::Scalar);

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
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct SessionKeyShares<G: Group> {
    /// The share of the pseudonym session key.
    pub pseudonym: PseudonymSessionKeyShare<G>,
    /// The share of the attribute session key.
    pub attribute: AttributeSessionKeyShare<G>,
}

/// Create a session key share from a rekey factor and blinding factor.
/// Automatically works for both pseudonym and attribute key shares based on the types.
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

redacted_debug!(PseudonymSessionKeyShare<G>, AttributeSessionKeyShare<G>);
zeroize_fields!(
    PseudonymSessionKeyShare<G> { 0 },
    AttributeSessionKeyShare<G> { 0 },
    SessionKeyShares<G> { pseudonym, attribute },
);

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
pub struct SessionKeyShareProofs<G: Group> {
    /// The proof of the pseudonym session key share.
    pub pseudonym: SessionKeyShareProof<G>,
    /// The proof of the attribute session key share.
    pub attribute: SessionKeyShareProof<G>,
}

/// A session key share `u_i = b_i · k_i` with the proof `ZKP{U_i = b_i · K_i}` that it was made
/// from the committed blinding factor and rekey factor (Section 3.5 of the paper). The user
/// receiving the share checks it with
/// [`SessionKeyShareProof::verify_share`].
#[cfg(feature = "verifiable")]
pub fn make_session_key_share_with_proof<S: SessionKeyShare, R: Rng + CryptoRng>(
    rekey_factor: &S::Factor,
    blinding_factor: &BlindingFactor<S::Group>,
    rng: &mut R,
) -> Result<(S, SessionKeyShareProof<S::Group>), SessionKeyShareError> {
    if *blinding_factor.value() == <S::Group as Group>::scalar_one() {
        return Err(SessionKeyShareError::WeakBlinding);
    }
    let share = S::from_rekey_factor(rekey_factor, blinding_factor);
    let rekey_commitment = RekeyFactorCommitment::<S::Group>::new(&rekey_factor.scalar());
    let proof = SessionKeyShareProof::new(blinding_factor.value(), &rekey_commitment.point(), rng);
    Ok((share, proof))
}

/// A [`PseudonymSessionKeyShare`] with its proof; see [`make_session_key_share_with_proof`].
#[cfg(feature = "verifiable")]
pub fn make_pseudonym_session_key_share_with_proof<G: Group, R: Rng + CryptoRng>(
    rekey_factor: &PseudonymRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
    rng: &mut R,
) -> Result<(PseudonymSessionKeyShare<G>, SessionKeyShareProof<G>), SessionKeyShareError> {
    make_session_key_share_with_proof(rekey_factor, blinding_factor, rng)
}

/// An [`AttributeSessionKeyShare`] with its proof; see [`make_session_key_share_with_proof`].
#[cfg(feature = "verifiable")]
pub fn make_attribute_session_key_share_with_proof<G: Group, R: Rng + CryptoRng>(
    rekey_factor: &AttributeRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
    rng: &mut R,
) -> Result<(AttributeSessionKeyShare<G>, SessionKeyShareProof<G>), SessionKeyShareError> {
    make_session_key_share_with_proof(rekey_factor, blinding_factor, rng)
}

/// Both session key shares with their proofs; see [`make_session_key_share_with_proof`].
#[cfg(feature = "verifiable")]
pub fn make_session_key_shares_with_proof<G: Group, R: Rng + CryptoRng>(
    pseudonym_rekey_factor: &PseudonymRekeyFactor<G>,
    attribute_rekey_factor: &AttributeRekeyFactor<G>,
    blinding_factor: &BlindingFactor<G>,
    rng: &mut R,
) -> Result<(SessionKeyShares<G>, SessionKeyShareProofs<G>), SessionKeyShareError> {
    let (pseudonym, pseudonym_proof) =
        make_pseudonym_session_key_share_with_proof(pseudonym_rekey_factor, blinding_factor, rng)?;
    let (attribute, attribute_proof) =
        make_attribute_session_key_share_with_proof(attribute_rekey_factor, blinding_factor, rng)?;
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
