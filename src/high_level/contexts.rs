use derive_more::{Deref, From};
use serde::{Deserialize, Serialize};
use crate::arithmetic::ScalarNonZero;
use crate::high_level::keys::{EncryptionSecret, PseudonymizationSecret};
use crate::high_level::utils::{make_pseudonymisation_factor, make_rekey_factor};

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
pub struct ReshuffleFactor(pub(crate) ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RekeyFactor(pub(crate) ScalarNonZero);

#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct Reshuffle2Factors {
    pub from: ReshuffleFactor,
    pub to: ReshuffleFactor,
    // TODO: optimization is possible by computing from^-1 * to once and use it all the time
}
#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct Rekey2Factors {
    pub from: RekeyFactor,
    pub to: RekeyFactor,
    // TODO: optimization is possible by computing from^-1 * to once and use it all the time
}
#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct RSK2Factors {
    pub s: Reshuffle2Factors,
    pub k: Rekey2Factors,
}

impl Reshuffle2Factors {
    pub fn reverse(self) -> Self {
        Reshuffle2Factors {
            from: self.to,
            to: self.from,
        }
    }
}
impl Rekey2Factors {
    pub fn reverse(self) -> Self {
        Rekey2Factors {
            from: self.to,
            to: self.from,
        }
    }
}

pub type PseudonymizationInfo = RSK2Factors;
pub type RekeyInfo = Rekey2Factors;
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
        let reshuffle_factors = Reshuffle2Factors {
            from: s_from,
            to: s_to,
        };
        let rekey_factors = RekeyInfo::new(from_enc_context, to_enc_context, encryption_secret);
        RSK2Factors {
            s: reshuffle_factors,
            k: rekey_factors,
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
        let reshuffle_factors = Reshuffle2Factors {
            from: s_from,
            to: s_to,
        };
        let rekey_factors = RekeyInfo::new_from_global(to_enc_context, encryption_secret);
        RSK2Factors {
            s: reshuffle_factors,
            k: rekey_factors,
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
        let reshuffle_factors = Reshuffle2Factors {
            from: s_from,
            to: s_to,
        };
        let rekey_factors = RekeyInfo::new_to_global(from_enc_context, encryption_secret);
        RSK2Factors {
            s: reshuffle_factors,
            k: rekey_factors,
        }
    }
    pub fn reverse(self) -> Self {
        RSK2Factors {
            s: self.s.reverse(),
            k: self.k.reverse(),
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
        Rekey2Factors {
            from: k_from,
            to: k_to,
        }
    }
    pub fn new_from_global(
        to_session: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_to = make_rekey_factor(&encryption_secret, &to_session);
        Rekey2Factors {
            from: RekeyFactor::from(ScalarNonZero::one()),
            to: k_to,
        }
    }
    pub fn new_to_global(
        from_session: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_rekey_factor(&encryption_secret, &from_session);
        Rekey2Factors {
            from: k_from,
            to: RekeyFactor::from(ScalarNonZero::one()),
        }
    }
}
impl From<PseudonymizationInfo> for RekeyInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        x.k
    }
}

pub type TranscryptionInfo = PseudonymizationInfo;