//! Helpers shared by the benchmarks: run a ciphertext through a chain of distributed
//! transcryptors.
//!
//! Every transcryption rerandomizes, which (without `elgamal3`) needs the public key the ciphertext
//! is currently encrypted under. The helpers carry that key along the chain, so that the
//! benchmarks measure a correct end-to-end flow in both ciphertext encodings.
#![allow(dead_code, clippy::expect_used)]

use libpep::data::traits::{Encryptable, Encrypted, HasStructure, Rekeyable, Transcryptable};
use libpep::factors::TranscryptionInfo;
use libpep::transcryptor::DistributedTranscryptor;
use rand_core::{CryptoRng, Rng};

type PublicKeyOf<E> = <<E as Encrypted>::UnencryptedType as Encryptable>::PublicKeyType;

/// Transcrypt `enc` through every transcryptor in turn.
#[allow(clippy::too_many_arguments)]
pub fn transcrypt_chain<E, R>(
    systems: &[DistributedTranscryptor],
    enc: E,
    key: PublicKeyOf<E>,
    info: impl Fn(&DistributedTranscryptor) -> TranscryptionInfo,
    next_key: impl Fn(&TranscryptionInfo, &PublicKeyOf<E>) -> PublicKeyOf<E>,
    rng: &mut R,
) -> E
where
    E: Transcryptable,
    R: Rng + CryptoRng,
{
    #[cfg(feature = "elgamal3")]
    {
        let _ = (key, next_key);
        systems.iter().fold(enc, |acc, system| {
            system.transcrypt(&acc, &info(system), rng)
        })
    }
    #[cfg(not(feature = "elgamal3"))]
    {
        systems
            .iter()
            .fold((enc, key), |(acc, key), system| {
                let info = info(system);
                (
                    system.transcrypt(&acc, &info, &key, rng),
                    next_key(&info, &key),
                )
            })
            .0
    }
}

/// Rekey `enc` through every transcryptor in turn.
pub fn rekey_chain<E, R>(
    systems: &[DistributedTranscryptor],
    enc: E,
    key: PublicKeyOf<E>,
    info: impl Fn(&DistributedTranscryptor) -> E::RekeyInfo,
    next_key: impl Fn(&E::RekeyInfo, &PublicKeyOf<E>) -> PublicKeyOf<E>,
    rng: &mut R,
) -> E
where
    E: Rekeyable,
    R: Rng + CryptoRng,
{
    #[cfg(feature = "elgamal3")]
    {
        let _ = (key, next_key);
        systems
            .iter()
            .fold(enc, |acc, system| system.rekey(&acc, &info(system), rng))
    }
    #[cfg(not(feature = "elgamal3"))]
    {
        systems
            .iter()
            .fold((enc, key), |(acc, key), system| {
                let info = info(system);
                (system.rekey(&acc, &info, &key, rng), next_key(&info, &key))
            })
            .0
    }
}

/// Transcrypt a batch through every transcryptor in turn.
#[cfg(feature = "batch")]
pub fn transcrypt_batch_chain<E, R>(
    systems: &[DistributedTranscryptor],
    mut batch: Vec<E>,
    key: PublicKeyOf<E>,
    info: impl Fn(&DistributedTranscryptor) -> TranscryptionInfo,
    next_key: impl Fn(&TranscryptionInfo, &PublicKeyOf<E>) -> PublicKeyOf<E>,
    rng: &mut R,
) -> Vec<E>
where
    E: Transcryptable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    #[cfg(feature = "elgamal3")]
    let _ = (&key, &next_key);
    #[cfg(not(feature = "elgamal3"))]
    let mut key = key;
    for system in systems {
        let info = info(system);
        #[cfg(feature = "elgamal3")]
        {
            batch = system
                .transcrypt_batch(&mut batch, &info, rng)
                .expect("transcrypt batch")
                .to_vec();
        }
        #[cfg(not(feature = "elgamal3"))]
        {
            batch = system
                .transcrypt_batch(&mut batch, &info, &key, rng)
                .expect("transcrypt batch")
                .to_vec();
            key = next_key(&info, &key);
        }
    }
    batch
}

/// Rekey a batch through every transcryptor in turn.
#[cfg(feature = "batch")]
pub fn rekey_batch_chain<E, R>(
    systems: &[DistributedTranscryptor],
    mut batch: Vec<E>,
    key: PublicKeyOf<E>,
    info: impl Fn(&DistributedTranscryptor) -> E::RekeyInfo,
    next_key: impl Fn(&E::RekeyInfo, &PublicKeyOf<E>) -> PublicKeyOf<E>,
    rng: &mut R,
) -> Vec<E>
where
    E: Rekeyable + HasStructure + Clone,
    E::RekeyInfo: Copy,
    R: Rng + CryptoRng,
{
    #[cfg(feature = "elgamal3")]
    let _ = (&key, &next_key);
    #[cfg(not(feature = "elgamal3"))]
    let mut key = key;
    for system in systems {
        let info = info(system);
        #[cfg(feature = "elgamal3")]
        {
            batch = system
                .rekey_batch(&mut batch, &info, rng)
                .expect("rekey batch")
                .to_vec();
        }
        #[cfg(not(feature = "elgamal3"))]
        {
            batch = system
                .rekey_batch(&mut batch, &info, &key, rng)
                .expect("rekey batch")
                .to_vec();
            key = next_key(&info, &key);
        }
    }
    batch
}
