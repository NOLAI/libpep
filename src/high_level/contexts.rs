use crate::high_level::keys::{EncryptionSecret, PseudonymizationSecret};
use crate::high_level::utils::{make_pseudonymisation_factor, make_rekey_factor};
use crate::internal::arithmetic::ScalarNonZero;
use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};

pub type Context = String; // Contexts are described by simple strings of arbitrary length
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, Serialize, Deserialize)]
pub struct PseudonymizationContext {
    #[deref]
    pub payload: Context,
    #[cfg(feature = "legacy-pep-repo-compatible")]
    pub audience_type: u32,
}
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, Serialize, Deserialize)]
pub struct EncryptionContext {
    #[deref]
    pub payload: Context,
    #[cfg(feature = "legacy-pep-repo-compatible")]
    pub audience_type: u32,
}
impl PseudonymizationContext {
    pub fn from(payload: &str) -> Self {
        PseudonymizationContext {
            payload: payload.to_string(),
            #[cfg(feature = "legacy-pep-repo-compatible")]
            audience_type: 0,
        }
    }
    #[cfg(feature = "legacy-pep-repo-compatible")]
    pub fn from_audience(payload: &str, audience_type: u32) -> Self {
        PseudonymizationContext {
            payload: payload.to_string(),
            audience_type,
        }
    }
}
impl EncryptionContext {
    pub fn from(payload: &str) -> Self {
        EncryptionContext {
            payload: payload.to_string(),
            #[cfg(feature = "legacy-pep-repo-compatible")]
            audience_type: 0,
        }
    }
    #[cfg(feature = "legacy-pep-repo-compatible")]
    pub fn from_audience(payload: &str, audience_type: u32) -> Self {
        EncryptionContext {
            payload: payload.to_string(),
            audience_type,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RerandomizeFactor(pub(crate) ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct ReshuffleFactor(pub(crate) ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RekeyFactor(pub(crate) ScalarNonZero);

#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct RSKFactors {
    pub s: ReshuffleFactor,
    pub k: RekeyFactor,
}

pub type PseudonymizationInfo = RSKFactors;
pub type RekeyInfo = RekeyFactor;
impl PseudonymizationInfo {
    pub fn new(
        from_pseudo_context: &PseudonymizationContext,
        to_pseudo_context: &PseudonymizationContext,
        from_enc_context: &EncryptionContext,
        to_enc_context: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_pseudo_context);
        let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_pseudo_context);
        let reshuffle_factor = ReshuffleFactor::from(s_from.0.invert() * &s_to.0);
        let rekey_factor = RekeyInfo::new(from_enc_context, to_enc_context, encryption_secret);
        Self {
            s: reshuffle_factor,
            k: rekey_factor,
        }
    }
    pub fn new_from_global(
        from_pseudo_context: &PseudonymizationContext,
        to_pseudo_context: &PseudonymizationContext,
        to_enc_context: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_pseudo_context);
        let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_pseudo_context);
        let reshuffle_factor = ReshuffleFactor::from(s_from.0.invert() * &s_to.0);
        let rekey_factor = RekeyInfo::new_from_global(to_enc_context, encryption_secret);
        Self {
            s: reshuffle_factor,
            k: rekey_factor,
        }
    }
    pub fn new_to_global(
        from_pseudo_context: &PseudonymizationContext,
        to_pseudo_context: &PseudonymizationContext,
        from_enc_context: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_pseudo_context);
        let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_pseudo_context);
        let reshuffle_factor = ReshuffleFactor::from(s_from.0.invert() * &s_to.0);
        let rekey_factor = RekeyInfo::new_to_global(from_enc_context, encryption_secret);
        Self {
            s: reshuffle_factor,
            k: rekey_factor,
        }
    }
    pub fn reverse(&self) -> Self {
        Self {
            s: ReshuffleFactor::from(self.s.0.invert()),
            k: RekeyFactor::from(self.k.0.invert()),
        }
    }
}
impl RekeyInfo {
    pub fn new(
        from_session: &EncryptionContext,
        to_session: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_rekey_factor(&encryption_secret, &from_session);
        let k_to = make_rekey_factor(&encryption_secret, &to_session);
        Self::from(k_from.0.invert() * &k_to.0)
    }
    pub fn new_from_global(
        to_session: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        Self::from(make_rekey_factor(&encryption_secret, &to_session))
    }
    pub fn new_to_global(
        from_session: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        Self::from(
            make_rekey_factor(&encryption_secret, &from_session)
                .0
                .invert(),
        )
    }
    pub fn reverse(&self) -> Self {
        Self::from(self.0.invert())
    }
}
impl From<PseudonymizationInfo> for RekeyInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        x.k
    }
}

pub type TranscryptionInfo = PseudonymizationInfo;
