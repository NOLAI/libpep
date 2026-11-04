//! The verification operations of the [`Verifier`]: against explicit commitments, against
//! cached commitments, and of session key shares.

use super::cache::CommitmentsCache;
use super::errors::VerifyError;
use super::verify::{PseudonymizationKey, RekeyTransitionKey, Verifier};
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::data::traits::Encrypted;
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable, VerifiableTranscryptable, VerifiableTranscryptionProof,
};
use crate::elgamal::arithmetic::ciphersuite::ElementOf;
use crate::elgamal::arithmetic::Ciphersuite;
use crate::factors::commitments::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
use crate::keys::distribution::proofs::SessionKeyShareProof;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::{PseudonymSessionPublicKey, SessionPublicKeys};

impl<C: Ciphersuite> Verifier<C> {
    // ------------------------------------------------------------------
    // Operation verification with explicit commitments
    // ------------------------------------------------------------------

    // ----- Rekey -----

    /// Verify a rekey proof against the given commitment.
    pub fn verify_rekey<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableRekeyCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableRekeyProof<Group = C::Group>,
    {
        Self::check_rekey_commitment(commitments, "rekey")?;
        if proof.verify::<C>(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    /// Verify a rekey proof against the given commitment and return the rekeyed value.
    pub fn verified_reconstruct_rekey<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableRekeyCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableRekeyProof<Group = C::Group>,
    {
        Self::check_rekey_commitment(commitments, "rekey")?;
        proof
            .verified_reconstruct::<C>(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    // ----- Pseudonymization -----

    #[cfg(feature = "elgamal3")]
    /// Verify a pseudonymization proof against the given commitments.
    pub fn verify_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiablePseudonymizationProof<Group = C::Group>,
    {
        Self::check_pseudonymization_commitment(commitments)?;
        if proof.verify::<C>(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify a pseudonymization proof against the given commitments; `public_key` is the key the
    /// original was encrypted under.
    pub fn verify_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &PseudonymSessionPublicKey<C::Group>,
        commitments: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiablePseudonymizationProof<Group = C::Group>,
    {
        Self::check_pseudonymization_commitment(commitments)?;
        if proof.verify::<C>(original, public_key, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(feature = "elgamal3")]
    /// Verify a pseudonymization proof against the given commitments and return the pseudonymized
    /// value.
    pub fn verified_reconstruct_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiablePseudonymizationProof<Group = C::Group>,
    {
        Self::check_pseudonymization_commitment(commitments)?;
        proof
            .verified_reconstruct::<C>(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify a pseudonymization proof against the given commitments and return the pseudonymized
    /// value; `public_key` is the key the original was encrypted under.
    pub fn verified_reconstruct_pseudonymization<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &PseudonymSessionPublicKey<C::Group>,
        commitments: &VerifiablePseudonymizationCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiablePseudonymizationProof<Group = C::Group>,
    {
        Self::check_pseudonymization_commitment(commitments)?;
        proof
            .verified_reconstruct::<C>(original, public_key, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    // ----- Transcryption (composite) -----

    #[cfg(feature = "elgamal3")]
    /// Verify a transcryption proof against the given commitments.
    pub fn verify_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableTranscryptionProof<Group = C::Group>,
    {
        Self::check_transcryption_commitment(commitments)?;
        if proof.verify::<C>(original, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify a transcryption proof against the given commitments; `public_key` holds the keys
    /// the original was encrypted under.
    pub fn verify_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &SessionPublicKeys<C::Group>,
        commitments: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<(), VerifyError>
    where
        P: VerifiableTranscryptionProof<Group = C::Group>,
    {
        Self::check_transcryption_commitment(commitments)?;
        if proof.verify::<C>(original, public_key, commitments) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }

    #[cfg(feature = "elgamal3")]
    /// Verify a transcryption proof against the given commitments and return the transcrypted
    /// value.
    pub fn verified_reconstruct_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        commitments: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableTranscryptionProof<Group = C::Group>,
    {
        Self::check_transcryption_commitment(commitments)?;
        proof
            .verified_reconstruct::<C>(original, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify a transcryption proof against the given commitments and return the transcrypted
    /// value; `public_key` holds the keys the original was encrypted under.
    pub fn verified_reconstruct_transcryption<P>(
        &self,
        original: &P::DataType,
        proof: &P,
        public_key: &SessionPublicKeys<C::Group>,
        commitments: &VerifiableTranscryptionCommitment<C::Group>,
    ) -> Result<P::Output, VerifyError>
    where
        P: VerifiableTranscryptionProof<Group = C::Group>,
    {
        Self::check_transcryption_commitment(commitments)?;
        proof
            .verified_reconstruct::<C>(original, public_key, commitments)
            .ok_or(VerifyError::ProofRejected)
    }

    // ------------------------------------------------------------------
    // Operation verification using cached commitments
    // ------------------------------------------------------------------

    /// Verify a pseudonymization proof using cached commitments for the
    /// given transition.
    #[cfg(feature = "elgamal3")]
    #[allow(clippy::too_many_arguments)]
    pub fn verified_reconstruct_pseudonymization_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::PseudonymizationProof,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::PseudonymizationProof as VerifiablePseudonymizationProof>::Output, VerifyError>
    where
        E: VerifiablePseudonymizable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::PseudonymizationProof: VerifiablePseudonymizationProof<DataType = E>,
    {
        let key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        let commitments = self
            .pseudonymization_cache
            .retrieve(&key)
            .ok_or(VerifyError::UnknownCommitment)?;
        self.verified_reconstruct_pseudonymization::<E::PseudonymizationProof>(
            original,
            proof,
            commitments,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    /// Verify a pseudonymization proof against the cached commitments of the transition and
    /// return the pseudonymized value; `public_key` is the key the original was encrypted under.
    pub fn verified_reconstruct_pseudonymization_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::PseudonymizationProof,
        public_key: &PseudonymSessionPublicKey<C::Group>,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::PseudonymizationProof as VerifiablePseudonymizationProof>::Output, VerifyError>
    where
        E: VerifiablePseudonymizable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::PseudonymizationProof: VerifiablePseudonymizationProof<DataType = E>,
    {
        let key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        let commitments = self
            .pseudonymization_cache
            .retrieve(&key)
            .ok_or(VerifyError::UnknownCommitment)?;
        self.verified_reconstruct_pseudonymization::<E::PseudonymizationProof>(
            original,
            proof,
            public_key,
            commitments,
        )
    }

    /// Verify a pseudonym rekey proof against the cached commitment of the transition and return
    /// the rekeyed value.
    pub fn verified_reconstruct_pseudonym_rekey_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::RekeyProof,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::RekeyProof as VerifiableRekeyProof>::Output, VerifyError>
    where
        E: VerifiableRekeyable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::RekeyProof: VerifiableRekeyProof<DataType = E>,
    {
        let key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        let commitments = self
            .pseudonym_rekey_cache
            .retrieve(&key)
            .ok_or(VerifyError::UnknownCommitment)?;
        self.verified_reconstruct_rekey::<E::RekeyProof>(original, proof, commitments)
    }

    /// Verify an attribute rekey proof against the cached commitment of the transition and return
    /// the rekeyed value.
    pub fn verified_reconstruct_attribute_rekey_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::RekeyProof,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::RekeyProof as VerifiableRekeyProof>::Output, VerifyError>
    where
        E: VerifiableRekeyable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::RekeyProof: VerifiableRekeyProof<DataType = E>,
    {
        let key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        let commitments = self
            .attribute_rekey_cache
            .retrieve(&key)
            .ok_or(VerifyError::UnknownCommitment)?;
        self.verified_reconstruct_rekey::<E::RekeyProof>(original, proof, commitments)
    }

    /// Verify a composite-value transcryption proof using cached commitments.
    #[cfg(feature = "elgamal3")]
    #[allow(clippy::too_many_arguments)]
    pub fn verified_reconstruct_transcryption_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::TranscryptionProof,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::TranscryptionProof as VerifiableTranscryptionProof>::Output, VerifyError>
    where
        E: VerifiableTranscryptable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::TranscryptionProof: VerifiableTranscryptionProof<DataType = E>,
    {
        let pseudo_key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        let attr_key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        let pseudonym = *self
            .pseudonymization_cache
            .retrieve(&pseudo_key)
            .ok_or(VerifyError::UnknownCommitment)?;
        let attribute = *self
            .attribute_rekey_cache
            .retrieve(&attr_key)
            .ok_or(VerifyError::UnknownCommitment)?;
        let commitments = VerifiableTranscryptionCommitment {
            pseudonym,
            attribute,
        };
        self.verified_reconstruct_transcryption::<E::TranscryptionProof>(
            original,
            proof,
            &commitments,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    /// Verify a transcryption proof against the cached commitments of the transition and return
    /// the transcrypted value; `public_key` holds the keys the original was encrypted under.
    pub fn verified_reconstruct_transcryption_cached<E>(
        &self,
        transcryptor_id: &str,
        original: &E,
        proof: &E::TranscryptionProof,
        public_key: &SessionPublicKeys<C::Group>,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        context_from: &EncryptionContext,
        context_to: &EncryptionContext,
    ) -> Result<<E::TranscryptionProof as VerifiableTranscryptionProof>::Output, VerifyError>
    where
        E: VerifiableTranscryptable<Group = C::Group> + Encrypted<Group = C::Group>,
        E::TranscryptionProof: VerifiableTranscryptionProof<DataType = E>,
    {
        let pseudo_key: PseudonymizationKey = (
            transcryptor_id.to_string(),
            domain_from.clone(),
            domain_to.clone(),
            context_from.clone(),
            context_to.clone(),
        );
        let attr_key: RekeyTransitionKey = (
            transcryptor_id.to_string(),
            context_from.clone(),
            context_to.clone(),
        );
        let pseudonym = *self
            .pseudonymization_cache
            .retrieve(&pseudo_key)
            .ok_or(VerifyError::UnknownCommitment)?;
        let attribute = *self
            .attribute_rekey_cache
            .retrieve(&attr_key)
            .ok_or(VerifyError::UnknownCommitment)?;
        let commitments = VerifiableTranscryptionCommitment {
            pseudonym,
            attribute,
        };
        self.verified_reconstruct_transcryption::<E::TranscryptionProof>(
            original,
            proof,
            public_key,
            &commitments,
        )
    }

    // ------------------------------------------------------------------
    // Session key share verification
    // ------------------------------------------------------------------

    // Session-share verification requires the session-level rekey
    // commitment, which the verifier does not cache (commitments are
    // per-transition). Use [`verify_session_key_share_with_commitment`]
    // and supply the rekey commitment explicitly.

    /// Verify a session-key-share proof against the registered blinding commitment of the
    /// transcryptor and an explicitly supplied rekey commitment.
    pub fn verify_session_key_share_with_commitment(
        &self,
        transcryptor_id: &str,
        rekey_commitment: &ElementOf<C>,
        proof: &SessionKeyShareProof<C::Group>,
    ) -> Result<(), VerifyError> {
        let blinding_commitment = self
            .blinding_commitment(transcryptor_id)
            .ok_or(VerifyError::UnknownCommitment)?;
        if proof.verify::<C>(blinding_commitment, rekey_commitment) {
            Ok(())
        } else {
            Err(VerifyError::ProofRejected)
        }
    }
}
