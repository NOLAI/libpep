//! Key generation functions for global and session keys.

use super::traits::SecretKey;
use super::types::*;
use crate::contexts::EncryptionContext;
use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use crate::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, EncryptionSecret, RekeyFactor,
};
use rand_core::{CryptoRng, Rng};

#[cfg(feature = "verifiable")]
use crate::elgamal::verifiable::RekeyFactorCommitment;
#[cfg(feature = "verifiable")]
use crate::keys::distribution::{BlindingCommitment, BlindingFactor, SessionKeyShareProof};

/// Generate a global key pair of the given secret key type.
///
/// The secret key is a random scalar; the public key is derived from it with
/// [`SecretKey::public_key`].
pub fn make_global_key_pair<R, SK>(rng: &mut R) -> (SK::PublicKeyType, SK)
where
    R: Rng + CryptoRng,
    SK: SecretKey,
{
    let scalar = loop {
        let scalar = ScalarNonZero::random(rng);
        if scalar != ScalarNonZero::one() {
            break scalar;
        }
    };
    let sk = SK::from_scalar(scalar);
    (sk.public_key(), sk)
}

/// Generate new global key pairs for both pseudonyms and attributes.
pub fn make_global_keys<R: Rng + CryptoRng>(rng: &mut R) -> (GlobalPublicKeys, GlobalSecretKeys) {
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
pub fn make_pseudonym_global_keys<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (PseudonymGlobalPublicKey, PseudonymGlobalSecretKey) {
    make_global_key_pair(rng)
}

/// Generate a new global key pair for attributes.
pub fn make_attribute_global_keys<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (AttributeGlobalPublicKey, AttributeGlobalSecretKey) {
    make_global_key_pair(rng)
}

/// Generate session keys for both pseudonyms and attributes from [`GlobalSecretKeys`], an [`EncryptionContext`] and an [`EncryptionSecret`].
pub fn make_session_keys(
    global: &GlobalSecretKeys,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> SessionKeys {
    let (pseudonym_public, pseudonym_secret) =
        make_pseudonym_session_keys(&global.pseudonym, context, secret);
    let (attribute_public, attribute_secret) =
        make_attribute_session_keys(&global.attribute, context, secret);
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
pub fn make_pseudonym_session_keys(
    global: &PseudonymGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
    let k = make_pseudonym_rekey_factor(secret, context);
    let sk = PseudonymSessionSecretKey::from_scalar(k.scalar() * *global.value());
    (sk.public_key(), sk)
}

/// Generate session keys for attributes from an [`AttributeGlobalSecretKey`], an [`EncryptionContext`] and an [`EncryptionSecret`].
///
/// The session secret key is the global secret key multiplied by the attribute rekey factor of
/// the context.
pub fn make_attribute_session_keys(
    global: &AttributeGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
    let k = make_attribute_rekey_factor(secret, context);
    let sk = AttributeSessionSecretKey::from_scalar(k.scalar() * *global.value());
    (sk.public_key(), sk)
}

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
pub fn make_session_key_pair_with_proof<GSK, SK, RF, F, R>(
    global: &GSK,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
    blinding: &BlindingFactor,
    rekey_fn: F,
    rng: &mut R,
) -> Result<
    (
        SK::PublicKeyType,
        SK,
        SessionKeyShareProof,
        BlindingCommitment,
    ),
    SessionKeyShareError,
>
where
    GSK: SecretKey,
    SK: SecretKey,
    RF: RekeyFactor,
    F: Fn(&EncryptionSecret, &EncryptionContext) -> RF,
    R: Rng + CryptoRng,
{
    // Refuse a degenerate blinding factor: `b_i = 1` yields `B_i = G` and
    // `u_i = k_i`, which leaks the share through public values.
    if *blinding.value() == ScalarNonZero::one() {
        return Err(SessionKeyShareError::WeakBlinding);
    }

    let k = rekey_fn(secret, context);
    let share = *blinding.value() * k.scalar();
    let sk = SK::from_scalar(share * *global.value());

    let blinding_commitment = BlindingCommitment::new(blinding.value());
    let rekey_commitment = RekeyFactorCommitment::new(&k.scalar());
    let proof = SessionKeyShareProof::new(blinding.value(), &rekey_commitment.0 .0, rng);

    Ok((sk.public_key(), sk, proof, blinding_commitment))
}

/// Generate pseudonym session keys with a proof of correct construction.
///
/// The returned proof should only be shared with the user requesting the session key, not
/// publicly, as it contains information about the session key share.
#[cfg(feature = "verifiable")]
pub fn make_pseudonym_session_keys_with_proof<R: Rng + CryptoRng>(
    global: &PseudonymGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
    blinding: &BlindingFactor,
    rng: &mut R,
) -> Result<
    (
        PseudonymSessionPublicKey,
        PseudonymSessionSecretKey,
        SessionKeyShareProof,
        BlindingCommitment,
    ),
    SessionKeyShareError,
> {
    make_session_key_pair_with_proof(
        global,
        context,
        secret,
        blinding,
        make_pseudonym_rekey_factor,
        rng,
    )
}

/// Generate attribute session keys with a proof of correct construction.
///
/// The returned proof should only be shared with the user requesting the session key, not
/// publicly, as it contains information about the session key share.
#[cfg(feature = "verifiable")]
pub fn make_attribute_session_keys_with_proof<R: Rng + CryptoRng>(
    global: &AttributeGlobalSecretKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
    blinding: &BlindingFactor,
    rng: &mut R,
) -> Result<
    (
        AttributeSessionPublicKey,
        AttributeSessionSecretKey,
        SessionKeyShareProof,
        BlindingCommitment,
    ),
    SessionKeyShareError,
> {
    make_session_key_pair_with_proof(
        global,
        context,
        secret,
        blinding,
        make_attribute_rekey_factor,
        rng,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    // The basepoint is imported so the assertions verify the derivation independently of
    // `public_key()`.
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::keys::traits::PublicKey;

    #[test]
    fn make_global_keys_creates_valid_keypairs() {
        let mut rng = rand::rng();
        let (public, secret) = make_global_keys(&mut rng);

        assert_eq!(*public.pseudonym, *secret.pseudonym.value() * G);
        assert_eq!(*public.attribute, *secret.attribute.value() * G);
    }

    #[test]
    fn make_pseudonym_global_keys_creates_valid_keypair() {
        let mut rng = rand::rng();
        let (public, secret) = make_global_key_pair::<_, PseudonymGlobalSecretKey>(&mut rng);
        assert_eq!(*public, *secret.value() * G);
    }

    #[test]
    fn make_attribute_global_keys_creates_valid_keypair() {
        let mut rng = rand::rng();
        let (public, secret) = make_global_key_pair::<_, AttributeGlobalSecretKey>(&mut rng);
        assert_eq!(*public, *secret.value() * G);
    }

    #[test]
    fn public_key_matches_derivation() {
        let mut rng = rand::rng();
        let (public, secret) = make_pseudonym_global_keys(&mut rng);
        assert_eq!(public, secret.public_key());
    }

    #[test]
    fn make_session_keys_derives_from_global() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());

        let session = make_session_keys(&global_sk, &context, &secret);

        assert_eq!(
            *session.pseudonym.public,
            *session.pseudonym.secret.value() * G
        );
        assert_eq!(
            *session.attribute.public,
            *session.attribute.secret.value() * G
        );
    }

    #[test]
    fn session_keys_deterministic() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());

        let session1 = make_session_keys(&global_sk, &context, &secret);
        let session2 = make_session_keys(&global_sk, &context, &secret);

        assert_eq!(session1, session2);
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let secret = EncryptionSecret::from(b"test-secret".to_vec());

        let session1 = make_session_keys(&global_sk, &EncryptionContext::from("context1"), &secret);
        let session2 = make_session_keys(&global_sk, &EncryptionContext::from("context2"), &secret);

        assert_ne!(session1, session2);
    }

    #[test]
    fn public_key_encode_decode() {
        let mut rng = rand::rng();
        let (public, _) = make_pseudonym_global_keys(&mut rng);
        let encoded = public.to_bytes();
        let decoded =
            PseudonymGlobalPublicKey::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(public, decoded);
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let mut rng = rand::rng();
        let (public, _) = make_attribute_global_keys(&mut rng);
        let hex = public.to_hex();
        let decoded =
            AttributeGlobalPublicKey::from_hex(&hex).expect("hex decoding should succeed");
        assert_eq!(public, decoded);
    }

    #[test]
    #[cfg(feature = "verifiable")]
    fn session_keys_with_proof_verify() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());
        let blinding = BlindingFactor::random(&mut rng);

        let (_pk, _sk, proof, commitment) = make_pseudonym_session_keys_with_proof(
            &global_sk.pseudonym,
            &context,
            &secret,
            &blinding,
            &mut rng,
        )
        .unwrap();
        let k = make_pseudonym_rekey_factor(&secret, &context);
        assert!(proof.verify(&commitment, &RekeyFactorCommitment::new(&k.scalar()).0 .0));
        assert_eq!(*commitment.value(), *blinding.value() * G);

        let (_pk, _sk, proof, commitment) = make_attribute_session_keys_with_proof(
            &global_sk.attribute,
            &context,
            &secret,
            &blinding,
            &mut rng,
        )
        .unwrap();
        let k = make_attribute_rekey_factor(&secret, &context);
        assert!(proof.verify(&commitment, &RekeyFactorCommitment::new(&k.scalar()).0 .0));
    }

    #[test]
    #[cfg(feature = "verifiable")]
    fn session_keys_with_proof_reject_unit_blinding() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());
        let blinding = BlindingFactor::from_scalar(ScalarNonZero::one());
        assert_eq!(
            make_pseudonym_session_keys_with_proof(
                &global_sk.pseudonym,
                &context,
                &secret,
                &blinding,
                &mut rng
            )
            .err(),
            Some(SessionKeyShareError::WeakBlinding)
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn session_secret_key_serde() {
        let mut rng = rand::rng();
        let (_global_pk, global_sk) = make_global_keys(&mut rng);
        let context = EncryptionContext::from("test");
        let secret = EncryptionSecret::from(b"secret".to_vec());

        let session = make_session_keys(&global_sk, &context, &secret);

        let json =
            serde_json::to_string(&session.pseudonym.secret).expect("serialization should succeed");
        let deserialized: PseudonymSessionSecretKey =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(session.pseudonym.secret, deserialized);
    }
}
