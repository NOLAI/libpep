//! The macro that instantiates the generic API for one group and ciphersuite.
//!
//! It is private to this crate on purpose. The `#[cfg(feature = "...")]` attributes in its body
//! are evaluated in the crate that expands it, and they must see libpep's features; a crate
//! that expanded a copy of it would evaluate them against its own. Other crates use the module
//! it is expanded into instead.

/// Declares type aliases, with the doc line each carries. Attributes in front of an entry (the
/// feature gates) are kept.
macro_rules! aliases {
    (
        $(
            $(#[$meta:meta])*
            $name:ident = $target:ty;
        )*
    ) => {
        $(
            $(#[$meta])*
            #[doc = concat!("Alias of `", stringify!($target), "`.")]
            pub type $name = $target;
        )*
    };
}

/// Instantiates the high-level API for a group `$G` (a [`Group`](crate::elgamal::arithmetic::Group))
/// and a ciphersuite `$C` (a [`Ciphersuite`](crate::elgamal::arithmetic::Ciphersuite) over `$G`):
/// aliases for every generic type, and wrappers for the functions whose group or ciphersuite
/// cannot be inferred from their arguments.
macro_rules! instantiate {
    ($G:ty, $C:ty) => {
        aliases! {
            // Data.
            Pseudonym = crate::data::simple::Pseudonym<$G>;
            Attribute = crate::data::simple::Attribute<$G>;
            EncryptedPseudonym = crate::data::simple::EncryptedPseudonym<$G>;
            EncryptedAttribute = crate::data::simple::EncryptedAttribute<$G>;
            #[cfg(feature = "long")]
            LongPseudonym = crate::data::long::LongPseudonym<$G>;
            #[cfg(feature = "long")]
            LongAttribute = crate::data::long::LongAttribute<$G>;
            #[cfg(feature = "long")]
            LongEncryptedPseudonym = crate::data::long::LongEncryptedPseudonym<$G>;
            #[cfg(feature = "long")]
            LongEncryptedAttribute = crate::data::long::LongEncryptedAttribute<$G>;
            Record = crate::data::records::Record<$G>;
            EncryptedRecord = crate::data::records::EncryptedRecord<$G>;
            #[cfg(feature = "long")]
            LongRecord = crate::data::records::LongRecord<$G>;
            #[cfg(feature = "long")]
            LongEncryptedRecord = crate::data::records::LongEncryptedRecord<$G>;
            #[cfg(feature = "json")]
            PepJsonBuilder = crate::data::json::PepJsonBuilder<$G>;
            #[cfg(feature = "json")]
            PepJsonValue = crate::data::json::PepJsonValue<$G>;
            #[cfg(feature = "json")]
            EncryptedPepJsonValue = crate::data::json::EncryptedPepJsonValue<$G>;
            ElGamal = crate::elgamal::ElGamal<$G>;

            // Keys.
            GlobalPublicKeys = crate::keys::GlobalPublicKeys<$G>;
            GlobalSecretKeys = crate::keys::GlobalSecretKeys<$G>;
            PseudonymGlobalPublicKey = crate::keys::PseudonymGlobalPublicKey<$G>;
            PseudonymGlobalSecretKey = crate::keys::PseudonymGlobalSecretKey<$G>;
            AttributeGlobalPublicKey = crate::keys::AttributeGlobalPublicKey<$G>;
            AttributeGlobalSecretKey = crate::keys::AttributeGlobalSecretKey<$G>;
            SessionKeys = crate::keys::SessionKeys<$G>;
            SessionPublicKeys = crate::keys::SessionPublicKeys<$G>;
            PseudonymSessionKeys = crate::keys::PseudonymSessionKeys<$G>;
            AttributeSessionKeys = crate::keys::AttributeSessionKeys<$G>;
            PseudonymSessionPublicKey = crate::keys::PseudonymSessionPublicKey<$G>;
            PseudonymSessionSecretKey = crate::keys::PseudonymSessionSecretKey<$G>;
            AttributeSessionPublicKey = crate::keys::AttributeSessionPublicKey<$G>;
            AttributeSessionSecretKey = crate::keys::AttributeSessionSecretKey<$G>;

            // Key distribution.
            BlindingFactor = crate::keys::distribution::BlindingFactor<$G>;
            BlindedPseudonymGlobalSecretKey = crate::keys::distribution::BlindedPseudonymGlobalSecretKey<$G>;
            BlindedAttributeGlobalSecretKey = crate::keys::distribution::BlindedAttributeGlobalSecretKey<$G>;
            BlindedGlobalSecretKeys = crate::keys::distribution::BlindedGlobalSecretKeys<$G>;
            PseudonymSessionKeyShare = crate::keys::distribution::PseudonymSessionKeyShare<$G>;
            AttributeSessionKeyShare = crate::keys::distribution::AttributeSessionKeyShare<$G>;
            SessionKeyShares = crate::keys::distribution::SessionKeyShares<$G>;
            #[cfg(feature = "verifiable")]
            BlindingCommitment = crate::keys::distribution::BlindingCommitment<$G>;
            #[cfg(feature = "verifiable")]
            SessionKeyShareProof = crate::keys::distribution::SessionKeyShareProof<$G>;
            #[cfg(feature = "verifiable")]
            SessionKeyShareProofs = crate::keys::distribution::SessionKeyShareProofs<$G>;

            // Factors.
            RerandomizeFactor = crate::factors::RerandomizeFactor<$G>;
            ReshuffleFactor = crate::factors::ReshuffleFactor<$G>;
            PseudonymRekeyFactor = crate::factors::PseudonymRekeyFactor<$G>;
            AttributeRekeyFactor = crate::factors::AttributeRekeyFactor<$G>;
            PseudonymizationInfo = crate::factors::PseudonymizationInfo<$G>;
            PseudonymRekeyInfo = crate::factors::PseudonymRekeyInfo<$G>;
            AttributeRekeyInfo = crate::factors::AttributeRekeyInfo<$G>;
            TranscryptionInfo = crate::factors::TranscryptionInfo<$G>;
            #[cfg(feature = "verifiable")]
            VerifiablePseudonymizationCommitment = crate::factors::VerifiablePseudonymizationCommitment<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRekeyCommitment = crate::factors::VerifiableRekeyCommitment<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableTranscryptionCommitment = crate::factors::VerifiableTranscryptionCommitment<$G>;
            #[cfg(feature = "verifiable")]
            FactorCommitment = crate::elgamal::verifiable::FactorCommitment<$G>;
            #[cfg(feature = "verifiable")]
            PseudonymizationFactorCommitment = crate::elgamal::verifiable::PseudonymizationFactorCommitment<$G>;
            #[cfg(feature = "verifiable")]
            RekeyFactorCommitment = crate::elgamal::verifiable::RekeyFactorCommitment<$G>;

            // Roles.
            Client = crate::client::Client<$G>;
            #[cfg(feature = "offline")]
            OfflineClient = crate::client::OfflineClient<$G>;

            // Proofs of the primitives.
            #[cfg(feature = "verifiable")]
            VerifiableRerandomize = crate::elgamal::verifiable::VerifiableRerandomize<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableReshuffle = crate::elgamal::verifiable::VerifiableReshuffle<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableReshuffle2 = crate::elgamal::verifiable::VerifiableReshuffle2<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRekey = crate::elgamal::verifiable::VerifiableRekey<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRekey2 = crate::elgamal::verifiable::VerifiableRekey2<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRSK = crate::elgamal::verifiable::VerifiableRSK<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRSK2 = crate::elgamal::verifiable::VerifiableRSK2<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRSKInner = crate::elgamal::verifiable::VerifiableRSKInner<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRRSK = crate::elgamal::verifiable::VerifiableRRSK<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRRSK2 = crate::elgamal::verifiable::VerifiableRRSK2<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRerandomizeBatch = crate::elgamal::verifiable::VerifiableRerandomizeBatch<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableReshuffleBatch = crate::elgamal::verifiable::VerifiableReshuffleBatch<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableReshuffle2Batch = crate::elgamal::verifiable::VerifiableReshuffle2Batch<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRekeyBatch = crate::elgamal::verifiable::VerifiableRekeyBatch<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRekey2Batch = crate::elgamal::verifiable::VerifiableRekey2Batch<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRSKBatch = crate::elgamal::verifiable::VerifiableRSKBatch<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRSK2Batch = crate::elgamal::verifiable::VerifiableRSK2Batch<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRRSKBatch = crate::elgamal::verifiable::VerifiableRRSKBatch<$G>;
            #[cfg(feature = "verifiable")]
            VerifiableRRSK2Batch = crate::elgamal::verifiable::VerifiableRRSK2Batch<$G>;

            // Proofs of the data types.
            #[cfg(feature = "verifiable")]
            PseudonymPseudonymizationProof = crate::data::verifiable::simple::PseudonymPseudonymizationProof<$G>;
            #[cfg(feature = "verifiable")]
            PseudonymRekeyProof = crate::data::verifiable::simple::PseudonymRekeyProof<$G>;
            #[cfg(feature = "verifiable")]
            AttributeRekeyProof = crate::data::verifiable::simple::AttributeRekeyProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "long"))]
            LongPseudonymPseudonymizationProof = crate::data::verifiable::long::LongPseudonymPseudonymizationProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "long"))]
            LongPseudonymRekeyProof = crate::data::verifiable::long::LongPseudonymRekeyProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "long"))]
            LongAttributeRekeyProof = crate::data::verifiable::long::LongAttributeRekeyProof<$G>;
            #[cfg(feature = "verifiable")]
            RecordTranscryptionProof = crate::data::verifiable::records::RecordTranscryptionProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "long"))]
            LongRecordTranscryptionProof = crate::data::verifiable::records::LongRecordTranscryptionProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "json"))]
            JsonTranscryptionProof = crate::data::verifiable::json::JsonTranscryptionProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch"))]
            PseudonymPseudonymizationBatchProof = crate::data::verifiable::simple::PseudonymPseudonymizationBatchProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch"))]
            PseudonymRekeyBatchProof = crate::data::verifiable::simple::PseudonymRekeyBatchProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch"))]
            AttributeRekeyBatchProof = crate::data::verifiable::simple::AttributeRekeyBatchProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch", feature = "long"))]
            LongPseudonymPseudonymizationBatchProof = crate::data::verifiable::long::LongPseudonymPseudonymizationBatchProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch", feature = "long"))]
            LongPseudonymRekeyBatchProof = crate::data::verifiable::long::LongPseudonymRekeyBatchProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch", feature = "long"))]
            LongAttributeRekeyBatchProof = crate::data::verifiable::long::LongAttributeRekeyBatchProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch"))]
            RecordTranscryptionBatchProof = crate::data::verifiable::records::RecordTranscryptionBatchProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch", feature = "long"))]
            LongRecordTranscryptionBatchProof = crate::data::verifiable::records::LongRecordTranscryptionBatchProof<$G>;
            #[cfg(all(feature = "verifiable", feature = "batch", feature = "json"))]
            JsonTranscryptionBatchProof = crate::data::verifiable::json::JsonTranscryptionBatchProof<$G>;

            // The verifier's caches.
            #[cfg(feature = "verifiable")]
            PseudonymizationCommitmentsCache = crate::verifier::PseudonymizationCommitmentsCache<$G>;
            #[cfg(feature = "verifiable")]
            PseudonymRekeyCommitmentsCache = crate::verifier::PseudonymRekeyCommitmentsCache<$G>;
            #[cfg(feature = "verifiable")]
            AttributeRekeyCommitmentsCache = crate::verifier::AttributeRekeyCommitmentsCache<$G>;
        }

        aliases! {
            Transcryptor = crate::transcryptor::Transcryptor<$C>;
            DistributedTranscryptor = crate::transcryptor::DistributedTranscryptor<$C>;
            #[cfg(feature = "verifiable")]
            Verifier = crate::verifier::Verifier<$C>;
            #[cfg(feature = "verifiable-derivation")]
            MasterPseudonymizationSecret = crate::factors::MasterPseudonymizationSecret<$C>;
            #[cfg(feature = "verifiable-derivation")]
            MasterPseudonymizationPublicKey = crate::factors::MasterPseudonymizationPublicKey<$C>;
            #[cfg(feature = "verifiable-derivation")]
            MasterRekeyingSecret = crate::factors::MasterRekeyingSecret<$C>;
            #[cfg(feature = "verifiable-derivation")]
            MasterRekeyingPublicKey = crate::factors::MasterRekeyingPublicKey<$C>;
        }

        /// [`VerifierCache`](crate::verifier::VerifierCache) instantiated for this group.
        #[cfg(feature = "verifiable")]
        pub type VerifierCache<'a> = crate::verifier::VerifierCache<'a, $G>;

        /// [`make_global_keys`](crate::keys::make_global_keys) for this group.
        pub fn make_global_keys<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            rng: &mut R,
        ) -> (GlobalPublicKeys, GlobalSecretKeys) {
            crate::keys::make_global_keys::<$G, R>(rng)
        }

        /// [`make_pseudonym_global_keys`](crate::keys::make_pseudonym_global_keys) for this group.
        pub fn make_pseudonym_global_keys<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            rng: &mut R,
        ) -> (PseudonymGlobalPublicKey, PseudonymGlobalSecretKey) {
            crate::keys::make_pseudonym_global_keys::<$G, R>(rng)
        }

        /// [`make_attribute_global_keys`](crate::keys::make_attribute_global_keys) for this group.
        pub fn make_attribute_global_keys<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            rng: &mut R,
        ) -> (AttributeGlobalPublicKey, AttributeGlobalSecretKey) {
            crate::keys::make_attribute_global_keys::<$G, R>(rng)
        }

        /// [`make_session_keys`](crate::keys::make_session_keys) for this ciphersuite.
        pub fn make_session_keys(
            global: &GlobalSecretKeys,
            session: &crate::contexts::EncryptionContext,
            secret: &crate::factors::EncryptionSecret,
        ) -> SessionKeys {
            crate::keys::make_session_keys::<$C>(global, session, secret)
        }

        /// [`make_pseudonym_session_keys`](crate::keys::make_pseudonym_session_keys) for this ciphersuite.
        pub fn make_pseudonym_session_keys(
            global: &PseudonymGlobalSecretKey,
            session: &crate::contexts::EncryptionContext,
            secret: &crate::factors::EncryptionSecret,
        ) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
            crate::keys::make_pseudonym_session_keys::<$C>(global, session, secret)
        }

        /// [`make_attribute_session_keys`](crate::keys::make_attribute_session_keys) for this ciphersuite.
        pub fn make_attribute_session_keys(
            global: &AttributeGlobalSecretKey,
            session: &crate::contexts::EncryptionContext,
            secret: &crate::factors::EncryptionSecret,
        ) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
            crate::keys::make_attribute_session_keys::<$C>(global, session, secret)
        }

        /// [`make_distributed_global_keys`](crate::keys::distribution::make_distributed_global_keys) for this group.
        pub fn make_distributed_global_keys<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            n: usize,
            rng: &mut R,
        ) -> (GlobalPublicKeys, BlindedGlobalSecretKeys, Vec<BlindingFactor>) {
            crate::keys::distribution::make_distributed_global_keys::<$G, R>(n, rng)
        }

        /// [`make_distributed_pseudonym_global_keys`](crate::keys::distribution::make_distributed_pseudonym_global_keys) for this group.
        pub fn make_distributed_pseudonym_global_keys<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            n: usize,
            rng: &mut R,
        ) -> (
            PseudonymGlobalPublicKey,
            BlindedPseudonymGlobalSecretKey,
            Vec<BlindingFactor>,
        ) {
            crate::keys::distribution::make_distributed_pseudonym_global_keys::<$G, R>(n, rng)
        }

        /// [`make_distributed_attribute_global_keys`](crate::keys::distribution::make_distributed_attribute_global_keys) for this group.
        pub fn make_distributed_attribute_global_keys<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            n: usize,
            rng: &mut R,
        ) -> (
            AttributeGlobalPublicKey,
            BlindedAttributeGlobalSecretKey,
            Vec<BlindingFactor>,
        ) {
            crate::keys::distribution::make_distributed_attribute_global_keys::<$G, R>(n, rng)
        }

        /// [`make_pseudonym_session_key_share_with_proof`](crate::keys::distribution::make_pseudonym_session_key_share_with_proof) for this ciphersuite.
        #[cfg(feature = "verifiable")]
        pub fn make_pseudonym_session_key_share_with_proof<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            rekey_factor: &PseudonymRekeyFactor,
            blinding_factor: &BlindingFactor,
            rng: &mut R,
        ) -> Result<
            (PseudonymSessionKeyShare, SessionKeyShareProof),
            crate::keys::distribution::SessionKeyShareError,
        > {
            crate::keys::distribution::make_pseudonym_session_key_share_with_proof::<$C, R>(
                rekey_factor,
                blinding_factor,
                rng,
            )
        }

        /// [`make_attribute_session_key_share_with_proof`](crate::keys::distribution::make_attribute_session_key_share_with_proof) for this ciphersuite.
        #[cfg(feature = "verifiable")]
        pub fn make_attribute_session_key_share_with_proof<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            rekey_factor: &AttributeRekeyFactor,
            blinding_factor: &BlindingFactor,
            rng: &mut R,
        ) -> Result<
            (AttributeSessionKeyShare, SessionKeyShareProof),
            crate::keys::distribution::SessionKeyShareError,
        > {
            crate::keys::distribution::make_attribute_session_key_share_with_proof::<$C, R>(
                rekey_factor,
                blinding_factor,
                rng,
            )
        }

        /// [`make_session_key_shares_with_proof`](crate::keys::distribution::make_session_key_shares_with_proof) for this ciphersuite.
        #[cfg(feature = "verifiable")]
        pub fn make_session_key_shares_with_proof<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            pseudonym_rekey_factor: &PseudonymRekeyFactor,
            attribute_rekey_factor: &AttributeRekeyFactor,
            blinding_factor: &BlindingFactor,
            rng: &mut R,
        ) -> Result<
            (SessionKeyShares, SessionKeyShareProofs),
            crate::keys::distribution::SessionKeyShareError,
        > {
            crate::keys::distribution::make_session_key_shares_with_proof::<$C, R>(
                pseudonym_rekey_factor,
                attribute_rekey_factor,
                blinding_factor,
                rng,
            )
        }

        /// [`make_pseudonymization_factor`](crate::factors::make_pseudonymization_factor) for this ciphersuite.
        pub fn make_pseudonymization_factor(
            secret: &crate::factors::PseudonymizationSecret,
            domain: &crate::contexts::PseudonymizationDomain,
        ) -> ReshuffleFactor {
            crate::factors::make_pseudonymization_factor::<$C>(secret, domain)
        }

        /// [`make_pseudonym_rekey_factor`](crate::factors::make_pseudonym_rekey_factor) for this ciphersuite.
        pub fn make_pseudonym_rekey_factor(
            secret: &crate::factors::EncryptionSecret,
            session: &crate::contexts::EncryptionContext,
        ) -> PseudonymRekeyFactor {
            crate::factors::make_pseudonym_rekey_factor::<$C>(secret, session)
        }

        /// [`make_attribute_rekey_factor`](crate::factors::make_attribute_rekey_factor) for this ciphersuite.
        pub fn make_attribute_rekey_factor(
            secret: &crate::factors::EncryptionSecret,
            session: &crate::contexts::EncryptionContext,
        ) -> AttributeRekeyFactor {
            crate::factors::make_attribute_rekey_factor::<$C>(secret, session)
        }

        /// [`PseudonymizationInfo::new`](crate::factors::PseudonymizationInfo::new) for this ciphersuite.
        pub fn pseudonymization_info(
            domain_from: &crate::contexts::PseudonymizationDomain,
            domain_to: &crate::contexts::PseudonymizationDomain,
            session_from: &crate::contexts::EncryptionContext,
            session_to: &crate::contexts::EncryptionContext,
            pseudonymization_secret: &crate::factors::PseudonymizationSecret,
            encryption_secret: &crate::factors::EncryptionSecret,
        ) -> PseudonymizationInfo {
            PseudonymizationInfo::new::<$C>(
                domain_from,
                domain_to,
                session_from,
                session_to,
                pseudonymization_secret,
                encryption_secret,
            )
        }

        /// [`PseudonymRekeyInfo::new`](crate::factors::PseudonymRekeyInfo::new) for this ciphersuite.
        pub fn pseudonym_rekey_info(
            session_from: &crate::contexts::EncryptionContext,
            session_to: &crate::contexts::EncryptionContext,
            encryption_secret: &crate::factors::EncryptionSecret,
        ) -> PseudonymRekeyInfo {
            PseudonymRekeyInfo::new::<$C>(session_from, session_to, encryption_secret)
        }

        /// [`AttributeRekeyInfo::new`](crate::factors::AttributeRekeyInfo::new) for this ciphersuite.
        pub fn attribute_rekey_info(
            session_from: &crate::contexts::EncryptionContext,
            session_to: &crate::contexts::EncryptionContext,
            encryption_secret: &crate::factors::EncryptionSecret,
        ) -> AttributeRekeyInfo {
            AttributeRekeyInfo::new::<$C>(session_from, session_to, encryption_secret)
        }

        /// [`TranscryptionInfo::new`](crate::factors::TranscryptionInfo::new) for this ciphersuite.
        pub fn transcryption_info(
            domain_from: &crate::contexts::PseudonymizationDomain,
            domain_to: &crate::contexts::PseudonymizationDomain,
            session_from: &crate::contexts::EncryptionContext,
            session_to: &crate::contexts::EncryptionContext,
            pseudonymization_secret: &crate::factors::PseudonymizationSecret,
            encryption_secret: &crate::factors::EncryptionSecret,
        ) -> TranscryptionInfo {
            TranscryptionInfo::new::<$C>(
                domain_from,
                domain_to,
                session_from,
                session_to,
                pseudonymization_secret,
                encryption_secret,
            )
        }

        /// [`hash_to_group`](crate::elgamal::arithmetic::hashing::hash_to_group) for this ciphersuite.
        #[must_use]
        pub fn hash_to_group(x: &[u8]) -> <$G as crate::elgamal::arithmetic::Group>::Element {
            crate::elgamal::arithmetic::hashing::hash_to_group::<$C>(x)
        }

        /// [`hash_to_nonzero_scalar`](crate::elgamal::arithmetic::hashing::hash_to_nonzero_scalar) for this ciphersuite.
        pub fn hash_to_nonzero_scalar(
            parts: &[&[u8]],
        ) -> <$G as crate::elgamal::arithmetic::Group>::Scalar {
            crate::elgamal::arithmetic::hashing::hash_to_nonzero_scalar::<$C>(parts)
        }

        /// [`verifiable_rerandomize`](crate::elgamal::verifiable::verifiable_rerandomize) for this ciphersuite.
        #[cfg(all(feature = "verifiable", feature = "insecure", feature = "elgamal3"))]
        pub fn verifiable_rerandomize<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            original: &ElGamal,
            r: &<$G as crate::elgamal::arithmetic::Group>::Scalar,
            rng: &mut R,
        ) -> (ElGamal, VerifiableRerandomize) {
            crate::elgamal::verifiable::verifiable_rerandomize::<$C, R>(original, r, rng)
        }

        /// [`verifiable_rerandomize`](crate::elgamal::verifiable::verifiable_rerandomize) for this ciphersuite.
        #[cfg(all(feature = "verifiable", feature = "insecure", not(feature = "elgamal3")))]
        pub fn verifiable_rerandomize<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            original: &ElGamal,
            gy: &<$G as crate::elgamal::arithmetic::Group>::Element,
            r: &<$G as crate::elgamal::arithmetic::Group>::Scalar,
            rng: &mut R,
        ) -> (ElGamal, VerifiableRerandomize) {
            crate::elgamal::verifiable::verifiable_rerandomize::<$C, R>(original, gy, r, rng)
        }

        /// [`verifiable_rerandomize_batch`](crate::elgamal::verifiable::verifiable_rerandomize_batch) for this ciphersuite.
        #[cfg(all(feature = "verifiable", feature = "insecure"))]
        pub fn verifiable_rerandomize_batch<R: ::rand_core::Rng + ::rand_core::CryptoRng>(
            originals: &[ElGamal],
            gy: &<$G as crate::elgamal::arithmetic::Group>::Element,
            rng: &mut R,
        ) -> (Vec<ElGamal>, VerifiableRerandomizeBatch) {
            crate::elgamal::verifiable::verifiable_rerandomize_batch::<$C, R>(originals, gy, rng)
        }
    };
}
