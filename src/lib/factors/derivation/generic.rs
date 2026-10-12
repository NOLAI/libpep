//! Factor derivation generic over the [`Group`].
//!
//! Three derivations exist, selected by feature:
//!
//! - The default is `DeriveFactor` of draft-doesburg-cfrg-coprf: `HashToScalar` over the
//!   length-prefixed secret, the label and the length-prefixed identifier, domain-separated with
//!   `"DeriveFactor-" || contextString` of the [ciphersuite](crate::elgamal::arithmetic::ciphersuite::Ciphersuite::current). A
//!   factor that is 0 or 1 is rejected and the derivation retried with the next counter.
//! - `hmac-derivation`: HMAC-SHA512 keyed with the secret over the label and the identifier, the
//!   derivation of libpep 0.13. It ignores the protocol context.
//! - `legacy`: the derivation of the legacy PEP repository.
//!
//! The labels are the same in every derivation: `0x01` pseudonym rekey, `0x02` attribute rekey,
//! `0x03` reshuffle.

use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::elgamal::arithmetic::group::Group;
use crate::factors::secrets::{EncryptionSecret, PseudonymizationSecret, Secret};
use crate::factors::types::generic::*;
#[cfg(any(feature = "legacy", feature = "hmac-derivation"))]
use hmac::{Hmac, KeyInit, Mac};
#[cfg(any(feature = "legacy", feature = "hmac-derivation"))]
use sha2::Sha512;
#[cfg(feature = "legacy")]
use sha2::{Digest, Sha256};

#[cfg(all(feature = "legacy", feature = "hmac-derivation"))]
compile_error!("the `legacy` and `hmac-derivation` features select different factor derivations and cannot be combined");

/// Label of the pseudonym rekey factor `k_c` (`labelRekeyPseudonym`).
pub const LABEL_REKEY_PSEUDONYM: u8 = 0x01;
/// Label of the attribute rekey factor `k'_c` (`labelRekeyAttribute`).
pub const LABEL_REKEY_ATTRIBUTE: u8 = 0x02;
/// Label of the reshuffle factor `s_d` (`labelReshuffle`).
pub const LABEL_RESHUFFLE: u8 = 0x03;

/// Derive a pseudonym rekey factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_pseudonym_rekey_factor<G: Group>(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
) -> PseudonymRekeyFactor<G> {
    match session {
        EncryptionContext::Specific(payload) => PseudonymRekeyFactor(make_factor::<G>(
            LABEL_REKEY_PSEUDONYM,
            &secret.0,
            payload.as_bytes(),
        )),
        #[cfg(feature = "offline")]
        EncryptionContext::Global => {
            // Global context - return identity factor
            PseudonymRekeyFactor(G::scalar_one())
        }
    }
}

/// Derive an attribute rekey factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_attribute_rekey_factor<G: Group>(
    secret: &EncryptionSecret,
    session: &EncryptionContext,
) -> AttributeRekeyFactor<G> {
    match session {
        EncryptionContext::Specific(payload) => AttributeRekeyFactor(make_factor::<G>(
            LABEL_REKEY_ATTRIBUTE,
            &secret.0,
            payload.as_bytes(),
        )),
        #[cfg(feature = "offline")]
        EncryptionContext::Global => {
            // Global context - return identity factor
            AttributeRekeyFactor(G::scalar_one())
        }
    }
}

/// Derive a pseudonymisation factor from a secret and a context.
#[cfg(not(feature = "legacy"))]
pub fn make_pseudonymisation_factor<G: Group>(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor<G> {
    match domain {
        PseudonymizationDomain::Specific(payload) => ReshuffleFactor(make_factor::<G>(
            LABEL_RESHUFFLE,
            &secret.0,
            payload.as_bytes(),
        )),
        #[cfg(feature = "global-pseudonyms")]
        PseudonymizationDomain::Global => {
            // Global domain - return identity factor
            ReshuffleFactor(G::scalar_one())
        }
    }
}

/// `DeriveFactor(secret, label, id)` of draft-doesburg-cfrg-coprf.
///
/// # Panics
///
/// Panics if `secret` or `id` is 2^16 bytes or longer; the derivation input length-prefixes
/// both with two bytes.
#[cfg(not(any(feature = "legacy", feature = "hmac-derivation")))]
pub(crate) fn make_factor<G: Group>(label: u8, secret: &Secret, id: &[u8]) -> G::Scalar {
    let secret_len = u16::try_from(secret.len()).ok();
    let id_len = u16::try_from(id.len()).ok();
    let (Some(secret_len), Some(id_len)) = (secret_len, id_len) else {
        panic!("DeriveFactor: secrets and identifiers must be shorter than 2^16 bytes");
    };
    let dst = crate::elgamal::arithmetic::ciphersuite::Ciphersuite::current().dst(b"DeriveFactor-");
    let mut input = Vec::with_capacity(secret.len() + id.len() + 6);
    input.extend_from_slice(&secret_len.to_be_bytes());
    input.extend_from_slice(secret);
    input.push(label);
    input.extend_from_slice(&id_len.to_be_bytes());
    input.extend_from_slice(id);
    // A factor must be neither 0 (which would destroy the ciphertext) nor 1 (which would apply no
    // transformation). Both occur with probability about 2^-252; if they do, the derivation is
    // retried with the next counter, so that it stays total and deterministic.
    for counter in 0u8..=255 {
        input.push(counter);
        let scalar = G::hash_to_scalar(&input, &dst).filter(|s| *s != G::scalar_one());
        input.pop();
        if let Some(factor) = scalar {
            return factor;
        }
    }
    unreachable!("256 consecutive degenerate factor derivations")
}

/// Derive a factor with HMAC-SHA512 keyed with the secret, the derivation of libpep 0.13.
#[cfg(feature = "hmac-derivation")]
pub(crate) fn make_factor<G: Group>(label: u8, secret: &Secret, id: &[u8]) -> G::Scalar {
    // Retried with a counter appended only on a degenerate result, so factors are unchanged in
    // the overwhelmingly common case.
    for counter in 0u8..=255 {
        // Unwrap is safe: HMAC-SHA512 accepts keys of any length
        #[allow(clippy::unwrap_used)]
        let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
        hmac.update(&u32::from(label).to_be_bytes());
        hmac.update(id);
        if counter > 0 {
            hmac.update(&[counter]);
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&hmac.finalize().into_bytes());
        if let Some(factor) = scalar_from_hash_excluding_zero_and_one::<G>(&bytes) {
            return factor;
        }
    }
    unreachable!("256 consecutive degenerate factor derivations")
}

/// Reduce a 64-byte hash to a scalar, rejecting 0 and 1.
#[cfg(feature = "hmac-derivation")]
pub(crate) fn scalar_from_hash_excluding_zero_and_one<G: Group>(
    bytes: &[u8; 64],
) -> Option<G::Scalar> {
    G::scalar_from_uniform_bytes(bytes).filter(|scalar| *scalar != G::scalar_one())
}

/// Derive a pseudonym rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_pseudonym_rekey_factor<G: Group>(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> PseudonymRekeyFactor<G> {
    match context {
        EncryptionContext::Specific {
            payload,
            audience_type,
        } => PseudonymRekeyFactor(make_factor::<G>(&secret.0, 0x02, *audience_type, payload)),
        EncryptionContext::Global => {
            // Global context - return identity factor
            PseudonymRekeyFactor(G::scalar_one())
        }
    }
}

/// Derive an attribute rekey factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_attribute_rekey_factor<G: Group>(
    secret: &EncryptionSecret,
    context: &EncryptionContext,
) -> AttributeRekeyFactor<G> {
    match context {
        EncryptionContext::Specific {
            payload,
            audience_type,
        } => AttributeRekeyFactor(make_factor::<G>(&secret.0, 0x01, *audience_type, payload)),
        EncryptionContext::Global => {
            // Global context - return identity factor
            AttributeRekeyFactor(G::scalar_one())
        }
    }
}

/// Derive a pseudonymisation factor from a secret and a context (using the legacy PEP repo method).
#[cfg(feature = "legacy")]
pub fn make_pseudonymisation_factor<G: Group>(
    secret: &PseudonymizationSecret,
    domain: &PseudonymizationDomain,
) -> ReshuffleFactor<G> {
    match domain {
        PseudonymizationDomain::Specific {
            payload,
            audience_type,
        } => ReshuffleFactor(make_factor::<G>(&secret.0, 0x01, *audience_type, payload)),
        PseudonymizationDomain::Global => {
            // Global domain - return identity factor
            ReshuffleFactor(G::scalar_one())
        }
    }
}

/// Derive a factor from a secret and a context (using the legacy PEP repo method).
///
/// As in the legacy implementation, a zero result is mapped to one.
#[cfg(feature = "legacy")]
fn make_factor<G: Group>(
    secret: &Secret,
    typ: u32,
    audience_type: u32,
    payload: &String,
) -> G::Scalar {
    let mut hasher_inner = Sha256::default();
    hasher_inner.update(typ.to_be_bytes());
    hasher_inner.update(audience_type.to_be_bytes());
    hasher_inner.update(payload.as_bytes());
    let result_inner = hasher_inner.finalize();

    // Unwrap is safe: HMAC-SHA512 accepts keys of any length
    #[allow(clippy::unwrap_used)]
    let mut hmac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
    hmac.update(&result_inner);
    let result_outer = hmac.finalize().into_bytes();

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&result_outer);
    G::scalar_from_uniform_bytes(&bytes).unwrap_or_else(G::scalar_one)
}

impl<G: Group> PseudonymizationInfo<G> {
    /// Compute the pseudonymization info given pseudonymization domains, sessions and secrets.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor::<G>(pseudonymization_secret, domain_from);
        let s_to = make_pseudonymisation_factor::<G>(pseudonymization_secret, domain_to);
        Self {
            s: ReshuffleFactor(G::scalar_inverse(&s_from.0) * s_to.0),
            k: PseudonymRekeyInfo::new(session_from, session_to, encryption_secret).k,
        }
    }
}

impl<G: Group> PseudonymRekeyInfo<G> {
    /// Compute the rekey info for pseudonyms given sessions and secrets.
    pub fn new(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_pseudonym_rekey_factor::<G>(encryption_secret, session_from);
        let k_to = make_pseudonym_rekey_factor::<G>(encryption_secret, session_to);
        Self {
            k: PseudonymRekeyFactor(G::scalar_inverse(&k_from.0) * k_to.0),
        }
    }
}

impl<G: Group> AttributeRekeyInfo<G> {
    /// Compute the rekey info for attributes given sessions and secrets.
    pub fn new(
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_attribute_rekey_factor::<G>(encryption_secret, session_from);
        let k_to = make_attribute_rekey_factor::<G>(encryption_secret, session_to);
        Self {
            k: AttributeRekeyFactor(G::scalar_inverse(&k_from.0) * k_to.0),
        }
    }
}

impl<G: Group> TranscryptionInfo<G> {
    /// Compute the transcryption info given pseudonymization domains, sessions and secrets.
    pub fn new(
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        Self {
            pseudonym: PseudonymizationInfo::new(
                domain_from,
                domain_to,
                session_from,
                session_to,
                pseudonymization_secret,
                encryption_secret,
            ),
            attribute: AttributeRekeyInfo::new(session_from, session_to, encryption_secret),
        }
    }
}
