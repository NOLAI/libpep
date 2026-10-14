//! Key generation generic over the [`Group`].

use crate::contexts::EncryptionContext;
use crate::elgamal::arithmetic::group::Group;
use crate::factors::derivation::generic::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor,
};
use crate::factors::types::generic::Factor;
use crate::factors::EncryptionSecret;
use crate::keys::traits::SecretKey;
use crate::keys::types::generic::*;
use rand_core::{CryptoRng, Rng};

/// Generate a global key pair of the given secret key type.
///
/// The secret key is a random scalar other than one; the public key is derived from it with
/// [`SecretKey::public_key`].
pub fn make_global_key_pair<R, SK>(rng: &mut R) -> (SK::PublicKeyType, SK)
where
    R: Rng + CryptoRng,
    SK: SecretKey,
{
    let scalar = loop {
        let scalar = SK::Group::random_scalar(rng);
        if scalar != SK::Group::scalar_one() {
            break scalar;
        }
    };
    let sk = SK::from_scalar(scalar);
    (sk.public_key(), sk)
}

/// Generate new global key pairs for both pseudonyms and attributes.
pub fn make_global_keys<G: Group, R: Rng + CryptoRng>(
    rng: &mut R,
) -> (GlobalPublicKeys<G>, GlobalSecretKeys<G>) {
    let (pseudonym_pk, pseudonym_sk) = make_pseudonym_global_keys(rng);
    let (attribute_pk, attribute_sk) = make_attribute_global_keys(rng);
    (
        GlobalPublicKeys {
            pseudonym: pseudonym_pk,
            attribute: attribute_pk,
        },
        GlobalSecretKeys {
            pseudonym: pseudonym_sk,
            attribute: attribute_sk,
        },
    )
}

/// Generate a new global key pair for pseudonyms.
pub fn make_pseudonym_global_keys<G: Group, R: Rng + CryptoRng>(
    rng: &mut R,
) -> (PseudonymGlobalPublicKey<G>, PseudonymGlobalSecretKey<G>) {
    make_global_key_pair(rng)
}

/// Generate a new global key pair for attributes.
pub fn make_attribute_global_keys<G: Group, R: Rng + CryptoRng>(
    rng: &mut R,
) -> (AttributeGlobalPublicKey<G>, AttributeGlobalSecretKey<G>) {
    make_global_key_pair(rng)
}

/// Generate session keys for both pseudonyms and attributes from [`GlobalSecretKeys`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_session_keys<G: Group>(
    global: &GlobalSecretKeys<G>,
    session: &EncryptionContext,
    secret: &EncryptionSecret,
) -> SessionKeys<G> {
    let (pseudonym_public, pseudonym_secret) =
        make_pseudonym_session_keys(&global.pseudonym, session, secret);
    let (attribute_public, attribute_secret) =
        make_attribute_session_keys(&global.attribute, session, secret);
    SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Generate session keys for pseudonyms from a [`PseudonymGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
///
/// The session secret key is the global secret key multiplied by the pseudonym rekey factor of
/// the context.
pub fn make_pseudonym_session_keys<G: Group>(
    global: &PseudonymGlobalSecretKey<G>,
    session: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (PseudonymSessionPublicKey<G>, PseudonymSessionSecretKey<G>) {
    let k = make_pseudonym_rekey_factor::<G>(secret, session);
    let sk = PseudonymSessionSecretKey::from_scalar(k.scalar() * *global.value());
    (sk.public_key(), sk)
}

/// Generate session keys for attributes from an [`AttributeGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
///
/// The session secret key is the global secret key multiplied by the attribute rekey factor of
/// the context.
pub fn make_attribute_session_keys<G: Group>(
    global: &AttributeGlobalSecretKey<G>,
    session: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (AttributeSessionPublicKey<G>, AttributeSessionSecretKey<G>) {
    let k = make_attribute_rekey_factor::<G>(secret, session);
    let sk = AttributeSessionSecretKey::from_scalar(k.scalar() * *global.value());
    (sk.public_key(), sk)
}

#[cfg(feature = "verifiable")]
use crate::elgamal::verifiable::generic::RekeyFactorCommitment;
#[cfg(feature = "verifiable")]
use crate::keys::distribution::blinding::generic::BlindingFactor;
#[cfg(feature = "verifiable")]
use crate::keys::distribution::proofs::generic::{BlindingCommitment, SessionKeyShareProof};

/// Reasons [`make_session_key_pair_with_proof`] (and its convenience wrappers)
/// can refuse to produce a session key share.
#[cfg(feature = "verifiable")]
#[derive(thiserror::Error, Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionKeyShareError {
    /// The supplied blinding factor was `1`. With `b_i = 1` the blinding
    /// commitment equals `G`, no blinding occurs, and the share scalar
    /// `u_i = k_i` is effectively published in the clear. Generate a fresh
    /// blinding factor (e.g. via [`BlindingFactor::random`](crate::keys::distribution::BlindingFactor::random),
    /// which excludes `1`) and retry.
    #[error("blinding factor must not be 1")]
    WeakBlinding,
}

/// The session key pair of a transcryptor's share, with the proof of the share and the
/// commitment to the blinding factor.
#[cfg(feature = "verifiable")]
pub type SessionKeysWithProof<PK, SK, G> =
    Result<(PK, SK, SessionKeyShareProof<G>, BlindingCommitment<G>), SessionKeyShareError>;

/// Generate a session key pair together with a proof of correct share construction.
///
/// This variant is part of libpep's **blinded-product key construction** (not a DKG / VSS
/// scheme). It returns the session key pair along with a zero-knowledge proof that the
/// session-key share `u_i = b_i * k_i` was constructed correctly, where `b_i` is the
/// transcryptor's blinding factor (committed to as `B_i = b_i·G`) and `k_i` is the publicly
/// recomputable rekey factor for the context.
///
/// The proof lets the user receiving the share verify it was honestly computed without learning
/// the secret factors. See [`crate::keys::distribution::proofs`] for the security model; in
/// particular this does **not** prove that the dealer used the matching `b_i` when blinding the
/// global secret key at setup time.
///
/// Returns the public session key, the secret session key (`u_i * global_secret`), the share
/// proof, and the blinding commitment `B_i = b_i * G`.
#[cfg(feature = "verifiable")]
pub fn make_session_key_pair_with_proof<G, GSK, SK, RF, F, R>(
    global: &GSK,
    session: &EncryptionContext,
    secret: &EncryptionSecret,
    blinding: &BlindingFactor<G>,
    rekey_fn: F,
    rng: &mut R,
) -> SessionKeysWithProof<SK::PublicKeyType, SK, G>
where
    G: Group,
    GSK: SecretKey<Group = G>,
    SK: SecretKey<Group = G>,
    RF: Factor<Group = G>,
    F: Fn(&EncryptionSecret, &EncryptionContext) -> RF,
    R: Rng + CryptoRng,
{
    // Refuse a degenerate blinding factor: `b_i = 1` yields `B_i = G` and
    // `u_i = k_i`, which leaks the share through public values.
    if *blinding.value() == G::scalar_one() {
        return Err(SessionKeyShareError::WeakBlinding);
    }

    let k = rekey_fn(secret, session);
    let share = *blinding.value() * k.scalar();
    let sk = SK::from_scalar(share * *global.value());

    let blinding_commitment = BlindingCommitment::new(blinding.value());
    let rekey_commitment = RekeyFactorCommitment::<G>::new(&k.scalar());
    let proof = SessionKeyShareProof::new(blinding.value(), &rekey_commitment.point(), rng);

    Ok((sk.public_key(), sk, proof, blinding_commitment))
}

/// Generate pseudonym session keys with a proof of correct construction.
///
/// The returned proof should only be shared with the user requesting the session key, not
/// publicly, as it contains information about the session key share.
#[cfg(feature = "verifiable")]
pub fn make_pseudonym_session_keys_with_proof<G: Group, R: Rng + CryptoRng>(
    global: &PseudonymGlobalSecretKey<G>,
    session: &EncryptionContext,
    secret: &EncryptionSecret,
    blinding: &BlindingFactor<G>,
    rng: &mut R,
) -> SessionKeysWithProof<PseudonymSessionPublicKey<G>, PseudonymSessionSecretKey<G>, G> {
    make_session_key_pair_with_proof(
        global,
        session,
        secret,
        blinding,
        make_pseudonym_rekey_factor::<G>,
        rng,
    )
}

/// Generate attribute session keys with a proof of correct construction.
///
/// The returned proof should only be shared with the user requesting the session key, not
/// publicly, as it contains information about the session key share.
#[cfg(feature = "verifiable")]
pub fn make_attribute_session_keys_with_proof<G: Group, R: Rng + CryptoRng>(
    global: &AttributeGlobalSecretKey<G>,
    session: &EncryptionContext,
    secret: &EncryptionSecret,
    blinding: &BlindingFactor<G>,
    rng: &mut R,
) -> SessionKeysWithProof<AttributeSessionPublicKey<G>, AttributeSessionSecretKey<G>, G> {
    make_session_key_pair_with_proof(
        global,
        session,
        secret,
        blinding,
        make_attribute_rekey_factor::<G>,
        rng,
    )
}
