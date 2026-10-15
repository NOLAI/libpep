//! Proofs of transcryption: `--prove` on a transcryption command produces one next to the
//! result, and the `verify-*` commands check one against the original ciphertext and the
//! transcryptor's commitments (`factors commitments`), reconstructing the result from it.
//!
//! A proof is the JSON serialization of the library's proof type; a commitment is a group
//! element (hex). A rekey proof is verified with `verify-rekey`, a pseudonymization proof (also
//! the one of `pseudonym transcrypt`) with `verify-pseudonymize`.

use crate::data::{Cipher, Kind, PseudonymKind};
use crate::io::{self, Output, Result};
use clap::Args;
use libpep::data::verifiable::long::LongPseudonymPseudonymizationProof;
use libpep::data::verifiable::simple::PseudonymPseudonymizationProof;
use libpep::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable,
};
use libpep::factors::commitments::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
};
use libpep::factors::PseudonymizationInfo;
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PseudonymSessionPublicKey;
use rand_core::{CryptoRng, Rng};

/// A proof made by the transcryptor verifies against the commitments to its own factors.
const FRESH_PROOF: &str = "a fresh proof verifies against its own commitments";

#[derive(Args)]
pub struct VerifyRekeyArgs {
    /// The transcryptor's commitment to the rekey factor (hex).
    #[arg(long)]
    rekey_commitment: String,
    /// The proof (JSON) the transcryptor produced with --prove.
    #[arg(long)]
    proof: String,
    /// The original ciphertext (base64), or the `|`-separated blocks of a long one.
    #[arg(allow_hyphen_values = true)]
    ciphertext: String,
}

#[derive(Args)]
pub struct VerifyPseudonymizeArgs {
    /// The public key the original ciphertext is encrypted under (hex).
    #[cfg(not(feature = "elgamal3"))]
    #[arg(long)]
    key: String,
    /// The transcryptor's commitment to the reshuffle factor (hex).
    #[arg(long)]
    reshuffle_commitment: String,
    /// The transcryptor's commitment to the rekey factor (hex).
    #[arg(long)]
    rekey_commitment: String,
    /// The proof (JSON) the transcryptor produced with --prove.
    #[arg(long)]
    proof: String,
    /// The original ciphertext (base64), or the `|`-separated blocks of a long one.
    #[arg(allow_hyphen_values = true)]
    ciphertext: String,
}

/// The rekey proof of a short or long ciphertext of one kind.
enum RekeyProof<K: Kind> {
    Short(<K::Enc as VerifiableRekeyable>::RekeyProof),
    Long(<K::LongEnc as VerifiableRekeyable>::RekeyProof),
}

impl<K: Kind> RekeyProof<K> {
    fn prove<R: Rng + CryptoRng>(cipher: &Cipher<K>, info: &K::RekeyInfo, rng: &mut R) -> Self {
        match cipher {
            Cipher::Short(c) => Self::Short(c.verifiable_rekey(info, rng)),
            Cipher::Long(c) => Self::Long(c.verifiable_rekey(info, rng)),
        }
    }

    /// Parse the proof of `original`, whose shape tells which proof type to expect.
    fn parse(raw: &str, original: &Cipher<K>) -> Result<Self> {
        Ok(match original {
            Cipher::Short(_) => Self::Short(io::json(raw, "proof")?),
            Cipher::Long(_) => Self::Long(io::json(raw, "proof")?),
        })
    }

    fn emit(&self, out: &mut Output) {
        match self {
            Self::Short(p) => out.value("proof", io::to_json(p)),
            Self::Long(p) => out.value("proof", io::to_json(p)),
        }
    }

    fn verified_reconstruct(
        &self,
        original: &Cipher<K>,
        commitment: &VerifiableRekeyCommitment,
    ) -> Option<Cipher<K>> {
        match (self, original) {
            (Self::Short(p), Cipher::Short(c)) => {
                p.verified_reconstruct(c, commitment).map(Cipher::Short)
            }
            (Self::Long(p), Cipher::Long(c)) => {
                p.verified_reconstruct(c, commitment).map(Cipher::Long)
            }
            _ => None,
        }
    }
}

/// The pseudonymization proof of a short or long encrypted pseudonym; both are large, so boxed.
enum PseudonymizationProof {
    Short(Box<PseudonymPseudonymizationProof>),
    Long(Box<LongPseudonymPseudonymizationProof>),
}

impl PseudonymizationProof {
    #[cfg(feature = "elgamal3")]
    fn prove<R: Rng + CryptoRng>(
        cipher: &Cipher<PseudonymKind>,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Self {
        match cipher {
            Cipher::Short(c) => Self::Short(Box::new(c.verifiable_pseudonymize(info, rng))),
            Cipher::Long(c) => Self::Long(Box::new(c.verifiable_pseudonymize(info, rng))),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn prove<R: Rng + CryptoRng>(
        cipher: &Cipher<PseudonymKind>,
        info: &PseudonymizationInfo,
        key: &PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> Self {
        match cipher {
            Cipher::Short(c) => Self::Short(Box::new(c.verifiable_pseudonymize(info, key, rng))),
            Cipher::Long(c) => Self::Long(Box::new(c.verifiable_pseudonymize(info, key, rng))),
        }
    }

    /// Parse the proof of `original`, whose shape tells which proof type to expect.
    fn parse(raw: &str, original: &Cipher<PseudonymKind>) -> Result<Self> {
        Ok(match original {
            Cipher::Short(_) => Self::Short(io::json(raw, "proof")?),
            Cipher::Long(_) => Self::Long(io::json(raw, "proof")?),
        })
    }

    fn emit(&self, out: &mut Output) {
        match self {
            Self::Short(p) => out.value("proof", io::to_json(p)),
            Self::Long(p) => out.value("proof", io::to_json(p)),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Cipher<PseudonymKind>,
        commitments: &VerifiablePseudonymizationCommitment,
    ) -> Option<Cipher<PseudonymKind>> {
        match (self, original) {
            (Self::Short(p), Cipher::Short(c)) => {
                p.verified_reconstruct(c, commitments).map(Cipher::Short)
            }
            (Self::Long(p), Cipher::Long(c)) => {
                p.verified_reconstruct(c, commitments).map(Cipher::Long)
            }
            _ => None,
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Cipher<PseudonymKind>,
        key: &PseudonymSessionPublicKey,
        commitments: &VerifiablePseudonymizationCommitment,
    ) -> Option<Cipher<PseudonymKind>> {
        match (self, original) {
            (Self::Short(p), Cipher::Short(c)) => p
                .verified_reconstruct(c, key, commitments)
                .map(Cipher::Short),
            (Self::Long(p), Cipher::Long(c)) => p
                .verified_reconstruct(c, key, commitments)
                .map(Cipher::Long),
            _ => None,
        }
    }
}

/// Rekey with a proof; emit the result and the proof.
pub fn prove_rekey<K: Kind, R: Rng + CryptoRng>(
    cipher: &Cipher<K>,
    info: &K::RekeyInfo,
    rng: &mut R,
    out: &mut Output,
) {
    let proof = RekeyProof::<K>::prove(cipher, info, rng);
    proof
        .verified_reconstruct(cipher, &(*info).into())
        .expect(FRESH_PROOF)
        .emit(out);
    proof.emit(out);
}

/// Pseudonymize with a proof; emit the result and the proof.
#[cfg(feature = "elgamal3")]
pub fn prove_pseudonymize<R: Rng + CryptoRng>(
    cipher: &Cipher<PseudonymKind>,
    info: &PseudonymizationInfo,
    rng: &mut R,
    out: &mut Output,
) {
    let proof = PseudonymizationProof::prove(cipher, info, rng);
    proof
        .verified_reconstruct(cipher, &(*info).into())
        .expect(FRESH_PROOF)
        .emit(out);
    proof.emit(out);
}

/// Pseudonymize with a proof; emit the result and the proof. `key` is the public key the
/// ciphertext is encrypted under.
#[cfg(not(feature = "elgamal3"))]
pub fn prove_pseudonymize<R: Rng + CryptoRng>(
    cipher: &Cipher<PseudonymKind>,
    info: &PseudonymizationInfo,
    key: &PseudonymSessionPublicKey,
    rng: &mut R,
    out: &mut Output,
) {
    let proof = PseudonymizationProof::prove(cipher, info, key, rng);
    proof
        .verified_reconstruct(cipher, key, &(*info).into())
        .expect(FRESH_PROOF)
        .emit(out);
    proof.emit(out);
}

pub fn verify_rekey<K: Kind>(args: VerifyRekeyArgs, out: &mut Output) -> Result<()> {
    let commitment = io::rekey_commitment(&args.rekey_commitment)?;
    let original = Cipher::<K>::parse(&args.ciphertext)?;
    let proof = RekeyProof::<K>::parse(&args.proof, &original)?;
    proof
        .verified_reconstruct(&original, &commitment)
        .ok_or_else(io::Error::invalid_proof)?
        .emit(out);
    Ok(())
}

pub fn verify_pseudonymize(args: VerifyPseudonymizeArgs, out: &mut Output) -> Result<()> {
    let commitments =
        io::pseudonymization_commitment(&args.reshuffle_commitment, &args.rekey_commitment)?;
    let original = Cipher::<PseudonymKind>::parse(&args.ciphertext)?;
    let proof = PseudonymizationProof::parse(&args.proof, &original)?;
    #[cfg(feature = "elgamal3")]
    let result = proof.verified_reconstruct(&original, &commitments);
    #[cfg(not(feature = "elgamal3"))]
    let result = {
        let key: PseudonymSessionPublicKey = io::public_key(&args.key, "public key")?;
        proof.verified_reconstruct(&original, &key, &commitments)
    };
    result.ok_or_else(io::Error::invalid_proof)?.emit(out);
    Ok(())
}
