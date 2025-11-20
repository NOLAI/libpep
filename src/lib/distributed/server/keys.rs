//! Session key share generation for distributed trust servers (transcryptors).

use crate::distributed::key_blinding::{
    AttributeSessionKeyShare, BlindingFactor, PseudonymSessionKeyShare, SessionKeyShares,
};
use crate::high_level::transcryption::contexts::{
    AttributeRekeyFactor, PseudonymRekeyFactor, RekeyFactor,
};

/// Create a [`PseudonymSessionKeyShare`] from a [`PseudonymRekeyFactor`] and a [`BlindingFactor`].
pub fn make_pseudonym_session_key_share(
    rekey_factor: &PseudonymRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> PseudonymSessionKeyShare {
    PseudonymSessionKeyShare::from(rekey_factor.scalar() * **blinding_factor)
}

/// Create an [`AttributeSessionKeyShare`] from an [`AttributeRekeyFactor`] and a [`BlindingFactor`].
pub fn make_attribute_session_key_share(
    rekey_factor: &AttributeRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> AttributeSessionKeyShare {
    AttributeSessionKeyShare::from(rekey_factor.scalar() * **blinding_factor)
}

/// Create [`SessionKeyShares`] (both pseudonym and attribute) from rekey factors and a blinding factor.
pub fn make_session_key_shares(
    pseudonym_rekey_factor: &PseudonymRekeyFactor,
    attribute_rekey_factor: &AttributeRekeyFactor,
    blinding_factor: &BlindingFactor,
) -> SessionKeyShares {
    SessionKeyShares {
        pseudonym: make_pseudonym_session_key_share(pseudonym_rekey_factor, blinding_factor),
        attribute: make_attribute_session_key_share(attribute_rekey_factor, blinding_factor),
    }
}
