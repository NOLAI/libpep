//! Session key shares for distributed transcryptors.
//!
//! A session key share is one transcryptor's contribution to a session key. Combining all shares
//! with the corresponding [blinded global secret key](super::blinding) yields the session key;
//! a single share reveals nothing about it on its own.
//!
//! Shares are protocol material, not keys: no data is encrypted towards them and they have no
//! associated public key, so they do not implement [`SecretKey`](crate::keys::SecretKey).
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances. The share functions infer the
//! group from the factors they are given.

pub mod generic;

pub use generic::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_share,
    make_session_key_shares, SessionKeyShare,
};
#[cfg(feature = "verifiable")]
pub use generic::{
    make_attribute_session_key_share_with_proof, make_pseudonym_session_key_share_with_proof,
    make_session_key_share_with_proof, make_session_key_shares_with_proof, SessionKeyShareError,
};

use crate::elgamal::arithmetic::Ristretto255;

/// The [`PseudonymSessionKeyShare`](generic::PseudonymSessionKeyShare) over ristretto255.
pub type PseudonymSessionKeyShare = generic::PseudonymSessionKeyShare<Ristretto255>;
/// The [`AttributeSessionKeyShare`](generic::AttributeSessionKeyShare) over ristretto255.
pub type AttributeSessionKeyShare = generic::AttributeSessionKeyShare<Ristretto255>;
/// The [`SessionKeyShares`](generic::SessionKeyShares) over ristretto255.
pub type SessionKeyShares = generic::SessionKeyShares<Ristretto255>;
/// The [`SessionKeyShareProofs`](generic::SessionKeyShareProofs) over ristretto255.
#[cfg(feature = "verifiable")]
pub type SessionKeyShareProofs = generic::SessionKeyShareProofs<Ristretto255>;

#[cfg(all(test, feature = "verifiable"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proof_tests {
    use super::*;
    use crate::contexts::EncryptionContext;
    use crate::elgamal::arithmetic::group_elements::G;
    use crate::elgamal::arithmetic::scalars::ScalarNonZero;
    use crate::elgamal::verifiable::RekeyFactorCommitment;
    use crate::factors::{
        make_attribute_rekey_factor, make_pseudonym_rekey_factor, EncryptionSecret, Factor,
    };
    use crate::keys::distribution::{BlindingCommitment, BlindingFactor};

    #[test]
    fn shares_with_proof_verify() {
        let mut rng = rand::rng();
        let session = EncryptionContext::from("test-context");
        let secret = EncryptionSecret::from(b"test-secret".to_vec());
        let blinding = BlindingFactor::random(&mut rng);
        let commitment = BlindingCommitment::new(blinding.value());
        assert_eq!(*commitment.value(), *blinding.value() * G);

        let k = make_pseudonym_rekey_factor(&secret, &session);
        let (share, proof) =
            make_pseudonym_session_key_share_with_proof(&k, &blinding, &mut rng).unwrap();
        let k_commitment = RekeyFactorCommitment::new(&k.scalar()).point();
        assert!(proof.verify_share(&share, &commitment, &k_commitment));

        let k = make_attribute_rekey_factor(&secret, &session);
        let (share, proof) =
            make_attribute_session_key_share_with_proof(&k, &blinding, &mut rng).unwrap();
        let k_commitment = RekeyFactorCommitment::new(&k.scalar()).point();
        assert!(proof.verify_share(&share, &commitment, &k_commitment));
    }

    #[test]
    fn shares_with_proof_reject_unit_blinding() {
        let mut rng = rand::rng();
        let k = make_pseudonym_rekey_factor(
            &EncryptionSecret::from(b"test-secret".to_vec()),
            &EncryptionContext::from("test-context"),
        );
        let blinding = BlindingFactor::from_scalar(ScalarNonZero::one());
        assert_eq!(
            make_pseudonym_session_key_share_with_proof(&k, &blinding, &mut rng).err(),
            Some(SessionKeyShareError::WeakBlinding)
        );
    }
}
