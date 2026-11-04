//! The public key a ciphertext is encrypted under after a transcryption: the
//! [`RekeyPublicKey`] trait, implemented by every [info](crate::factors::types) for the key of
//! the data it transcrypts.

use crate::factors::types::{
    AttributeRekeyInfo, Factor, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use crate::group::Group;
use crate::keys::traits::PublicKey;
use crate::keys::types::{AttributeSessionPublicKey, PseudonymSessionPublicKey, SessionPublicKeys};

/// The public key a ciphertext is encrypted under after a transcryption with this info, given
/// the key it was encrypted under before.
///
/// A transcryptor passes the key on with the ciphertext, so that the next transcryptor (or the
/// storage) can rerandomize it. Implemented for every info and the key, or key bundle, of the
/// data it transcrypts.
pub trait RekeyPublicKey<K> {
    /// The public key after rekeying `before` with this info: `k * before`.
    fn rekey_public_key(&self, before: &K) -> K;
}

impl<G: Group> RekeyPublicKey<PseudonymSessionPublicKey<G>> for PseudonymizationInfo<G> {
    fn rekey_public_key(
        &self,
        before: &PseudonymSessionPublicKey<G>,
    ) -> PseudonymSessionPublicKey<G> {
        PseudonymSessionPublicKey::from_point(self.k.scalar() * *before.value())
    }
}

impl<G: Group> RekeyPublicKey<PseudonymSessionPublicKey<G>> for PseudonymRekeyInfo<G> {
    fn rekey_public_key(
        &self,
        before: &PseudonymSessionPublicKey<G>,
    ) -> PseudonymSessionPublicKey<G> {
        PseudonymSessionPublicKey::from_point(self.k.scalar() * *before.value())
    }
}

impl<G: Group> RekeyPublicKey<AttributeSessionPublicKey<G>> for AttributeRekeyInfo<G> {
    fn rekey_public_key(
        &self,
        before: &AttributeSessionPublicKey<G>,
    ) -> AttributeSessionPublicKey<G> {
        AttributeSessionPublicKey::from_point(self.k.scalar() * *before.value())
    }
}

impl<G: Group> RekeyPublicKey<SessionPublicKeys<G>> for TranscryptionInfo<G> {
    fn rekey_public_key(&self, before: &SessionPublicKeys<G>) -> SessionPublicKeys<G> {
        SessionPublicKeys {
            pseudonym: self.pseudonym.rekey_public_key(&before.pseudonym),
            attribute: self.attribute.rekey_public_key(&before.attribute),
        }
    }
}

impl<G: Group> RekeyPublicKey<PseudonymSessionPublicKey<G>> for TranscryptionInfo<G> {
    fn rekey_public_key(
        &self,
        before: &PseudonymSessionPublicKey<G>,
    ) -> PseudonymSessionPublicKey<G> {
        self.pseudonym.rekey_public_key(before)
    }
}

impl<G: Group> RekeyPublicKey<AttributeSessionPublicKey<G>> for TranscryptionInfo<G> {
    fn rekey_public_key(
        &self,
        before: &AttributeSessionPublicKey<G>,
    ) -> AttributeSessionPublicKey<G> {
        self.attribute.rekey_public_key(before)
    }
}
