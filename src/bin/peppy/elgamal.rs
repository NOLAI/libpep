//! `peppy elgamal`: the raw primitives on ElGamal ciphertexts and scalar factors.
//!
//! These are the operations of the paper, without the pseudonym and attribute types on top:
//! `rr` (rerandomize), `rs` (reshuffle), `rk` (rekey), their combinations `rsk` and `rrsk`, and
//! the transitive `*2` variants that take the factors of both source and target.

use crate::io::{self, Output, Result};
use clap::Subcommand;
use libpep::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use libpep::elgamal::primitives;
use libpep::elgamal::{decrypt, encrypt};
use rand_core::{CryptoRng, Rng};

#[derive(Subcommand)]
pub enum Elgamal {
    /// Encrypt a group element for a public key (a group element).
    Encrypt {
        /// The public key (hex).
        #[arg(long)]
        key: String,
        message: String,
    },
    /// Decrypt a ciphertext with a secret key (a scalar).
    Decrypt {
        /// The secret key (hex).
        #[arg(long)]
        key: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Rerandomize: same message and key, different ciphertext.
    Rr {
        /// The rerandomization factor; random if omitted.
        #[arg(long)]
        r: Option<String>,
        /// The public key the ciphertext is encrypted under (hex).
        #[cfg(not(feature = "elgamal3"))]
        #[arg(long)]
        key: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Reshuffle: the message M becomes s * M.
    Rs {
        #[arg(long)]
        s: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Rekey: decryptable with k * y instead of y.
    Rk {
        #[arg(long)]
        k: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Reshuffle and rekey in one step.
    Rsk {
        #[arg(long)]
        s: String,
        #[arg(long)]
        k: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Rerandomize, reshuffle and rekey in one step.
    Rrsk {
        /// The rerandomization factor; random if omitted.
        #[arg(long)]
        r: Option<String>,
        #[arg(long)]
        s: String,
        #[arg(long)]
        k: String,
        /// The public key the ciphertext is encrypted under (hex).
        #[cfg(not(feature = "elgamal3"))]
        #[arg(long)]
        key: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Reshuffle from the domain with factor `from` to the domain with factor `to`.
    Rs2 {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Rekey from the context with factor `from` to the context with factor `to`.
    Rk2 {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Reshuffle and rekey between two domains and two contexts.
    Rsk2 {
        #[arg(long)]
        s_from: String,
        #[arg(long)]
        s_to: String,
        #[arg(long)]
        k_from: String,
        #[arg(long)]
        k_to: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
    /// Rerandomize, reshuffle and rekey between two domains and two contexts.
    Rrsk2 {
        /// The rerandomization factor; random if omitted.
        #[arg(long)]
        r: Option<String>,
        #[arg(long)]
        s_from: String,
        #[arg(long)]
        s_to: String,
        #[arg(long)]
        k_from: String,
        #[arg(long)]
        k_to: String,
        /// The public key the ciphertext is encrypted under (hex).
        #[cfg(not(feature = "elgamal3"))]
        #[arg(long)]
        key: String,
        #[arg(allow_hyphen_values = true)]
        ciphertext: String,
    },
}

fn factor<R: Rng + CryptoRng>(
    raw: Option<&str>,
    rng: &mut R,
    out: &mut Output,
) -> Result<ScalarNonZero> {
    match raw {
        Some(r) => io::scalar(r, "r"),
        None => {
            let r = ScalarNonZero::random(rng);
            out.value("rerandomize_factor", r.to_hex());
            Ok(r)
        }
    }
}

pub fn run<R: Rng + CryptoRng>(cmd: Elgamal, rng: &mut R, out: &mut Output) -> Result<()> {
    let result = match cmd {
        Elgamal::Encrypt { key, message } => encrypt(
            &io::point(&message, "message")?,
            &io::point(&key, "public key")?,
            rng,
        ),
        Elgamal::Decrypt { key, ciphertext } => {
            let key = io::scalar(&key, "secret key")?;
            let ciphertext = io::ciphertext(&ciphertext)?;
            #[cfg(feature = "elgamal3")]
            let message = decrypt(&ciphertext, &key).ok_or_else(io::Error::key_mismatch)?;
            #[cfg(not(feature = "elgamal3"))]
            let message = decrypt(&ciphertext, &key);
            out.value("message", message.to_hex());
            return Ok(());
        }
        Elgamal::Rr {
            r,
            #[cfg(not(feature = "elgamal3"))]
            key,
            ciphertext,
        } => {
            let ciphertext = io::ciphertext(&ciphertext)?;
            let r = factor(r.as_deref(), rng, out)?;
            #[cfg(feature = "elgamal3")]
            {
                primitives::rerandomize(&ciphertext, &r)
            }
            #[cfg(not(feature = "elgamal3"))]
            {
                primitives::rerandomize(&ciphertext, &io::point(&key, "public key")?, &r)
            }
        }
        Elgamal::Rs { s, ciphertext } => {
            primitives::reshuffle(&io::ciphertext(&ciphertext)?, &io::scalar(&s, "s")?)
        }
        Elgamal::Rk { k, ciphertext } => {
            primitives::rekey(&io::ciphertext(&ciphertext)?, &io::scalar(&k, "k")?)
        }
        Elgamal::Rsk { s, k, ciphertext } => primitives::rsk(
            &io::ciphertext(&ciphertext)?,
            &io::scalar(&s, "s")?,
            &io::scalar(&k, "k")?,
        ),
        Elgamal::Rrsk {
            r,
            s,
            k,
            #[cfg(not(feature = "elgamal3"))]
            key,
            ciphertext,
        } => {
            let ciphertext = io::ciphertext(&ciphertext)?;
            let s = io::scalar(&s, "s")?;
            let k = io::scalar(&k, "k")?;
            let r = factor(r.as_deref(), rng, out)?;
            #[cfg(feature = "elgamal3")]
            {
                primitives::rrsk(&ciphertext, &r, &s, &k)
            }
            #[cfg(not(feature = "elgamal3"))]
            {
                primitives::rrsk(&ciphertext, &io::point(&key, "public key")?, &r, &s, &k)
            }
        }
        Elgamal::Rs2 {
            from,
            to,
            ciphertext,
        } => primitives::reshuffle2(
            &io::ciphertext(&ciphertext)?,
            &io::scalar(&from, "from")?,
            &io::scalar(&to, "to")?,
        ),
        Elgamal::Rk2 {
            from,
            to,
            ciphertext,
        } => primitives::rekey2(
            &io::ciphertext(&ciphertext)?,
            &io::scalar(&from, "from")?,
            &io::scalar(&to, "to")?,
        ),
        Elgamal::Rsk2 {
            s_from,
            s_to,
            k_from,
            k_to,
            ciphertext,
        } => primitives::rsk2(
            &io::ciphertext(&ciphertext)?,
            &io::scalar(&s_from, "s-from")?,
            &io::scalar(&s_to, "s-to")?,
            &io::scalar(&k_from, "k-from")?,
            &io::scalar(&k_to, "k-to")?,
        ),
        Elgamal::Rrsk2 {
            r,
            s_from,
            s_to,
            k_from,
            k_to,
            #[cfg(not(feature = "elgamal3"))]
            key,
            ciphertext,
        } => {
            let ciphertext = io::ciphertext(&ciphertext)?;
            let s_from = io::scalar(&s_from, "s-from")?;
            let s_to = io::scalar(&s_to, "s-to")?;
            let k_from = io::scalar(&k_from, "k-from")?;
            let k_to = io::scalar(&k_to, "k-to")?;
            let r = factor(r.as_deref(), rng, out)?;
            #[cfg(feature = "elgamal3")]
            {
                primitives::rrsk2(&ciphertext, &r, &s_from, &s_to, &k_from, &k_to)
            }
            #[cfg(not(feature = "elgamal3"))]
            {
                primitives::rrsk2(
                    &ciphertext,
                    &io::point(&key, "public key")?,
                    &r,
                    &s_from,
                    &s_to,
                    &k_from,
                    &k_to,
                )
            }
        }
    };
    out.value("ciphertext", result.to_base64());
    Ok(())
}
