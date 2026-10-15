//! `peppy factors`: derive reshuffle and rekey factors from secrets, the info for a
//! transcryption between two domains and contexts, and the commitments to its factors that a
//! transcryptor publishes for verifiable transcryption.

use crate::io::{self, Output, Result};
use clap::{Args, Subcommand};
use libpep::elgamal::arithmetic::scalars::ScalarTraits;
use libpep::factors::commitments::VerifiableTranscryptionCommitment;
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymization_factor,
    AttributeRekeyInfo, Factor, TranscryptionInfo,
};

#[derive(Subcommand)]
pub enum Factors {
    /// The reshuffle factor of a pseudonymization domain.
    Reshuffle {
        /// The transcryptor's pseudonymization secret.
        #[arg(long)]
        pseudonymization_secret: String,
        /// The pseudonymization domain.
        #[arg(long)]
        domain: String,
    },
    /// The rekey factor of an encryption context.
    Rekey {
        /// The transcryptor's encryption secret.
        #[arg(long)]
        encryption_secret: String,
        /// The encryption context (session); omit for the global context.
        #[arg(long)]
        context: Option<String>,
        /// The attribute rekey factor instead of the pseudonym rekey factor.
        #[arg(long)]
        attribute: bool,
    },
    /// The factors that transcrypt from one domain and context to another: the ratios of the
    /// reshuffle and rekey factors of source and target.
    Info(TransitionArgs),
    /// The commitments to the factors of a transcryption, which a transcryptor publishes so that
    /// its proofs (`--prove`) can be verified.
    Commitments(TransitionArgs),
}

/// A transcryption transition: the transcryptor's secrets and the domains and contexts.
#[derive(Args)]
pub struct TransitionArgs {
    /// The transcryptor's pseudonymization secret.
    #[arg(long)]
    pseudonymization_secret: String,
    /// The transcryptor's encryption secret.
    #[arg(long)]
    encryption_secret: String,
    /// The pseudonymization domain the data comes from.
    #[arg(long)]
    from_domain: String,
    /// The pseudonymization domain the data goes to.
    #[arg(long)]
    to_domain: String,
    /// The encryption context the data comes from; omit for the global context.
    #[arg(long)]
    from_context: Option<String>,
    /// The encryption context the data goes to; omit for the global context.
    #[arg(long)]
    to_context: Option<String>,
}

/// A rekey transition of attributes: the transcryptor's encryption secret and the contexts.
#[derive(Args)]
pub struct AttributeTransitionArgs {
    /// The transcryptor's encryption secret.
    #[arg(long)]
    encryption_secret: String,
    /// The encryption context the data comes from; omit for the global context.
    #[arg(long)]
    from_context: Option<String>,
    /// The encryption context the data goes to; omit for the global context.
    #[arg(long)]
    to_context: Option<String>,
}

impl AttributeTransitionArgs {
    pub fn info(&self) -> Result<AttributeRekeyInfo> {
        Ok(AttributeRekeyInfo::new(
            &io::context(self.from_context.as_deref())?,
            &io::context(self.to_context.as_deref())?,
            &io::encryption_secret(&self.encryption_secret)?,
        ))
    }
}

impl TransitionArgs {
    pub fn info(&self) -> Result<TranscryptionInfo> {
        Ok(TranscryptionInfo::new(
            &io::domain(&self.from_domain)?,
            &io::domain(&self.to_domain)?,
            &io::context(self.from_context.as_deref())?,
            &io::context(self.to_context.as_deref())?,
            &io::pseudonymization_secret(&self.pseudonymization_secret)?,
            &io::encryption_secret(&self.encryption_secret)?,
        ))
    }
}

pub fn run(cmd: Factors, out: &mut Output) -> Result<()> {
    match cmd {
        Factors::Reshuffle {
            pseudonymization_secret,
            domain,
        } => {
            let factor = make_pseudonymization_factor(
                &io::pseudonymization_secret(&pseudonymization_secret)?,
                &io::domain(&domain)?,
            );
            out.value("reshuffle_factor", factor.scalar().to_hex());
        }
        Factors::Rekey {
            encryption_secret,
            context,
            attribute,
        } => {
            let secret = io::encryption_secret(&encryption_secret)?;
            let context = io::context(context.as_deref())?;
            let factor = if attribute {
                make_attribute_rekey_factor(&secret, &context).scalar()
            } else {
                make_pseudonym_rekey_factor(&secret, &context).scalar()
            };
            out.value("rekey_factor", factor.to_hex());
        }
        Factors::Info(transition) => {
            let info = transition.info()?;
            out.value("reshuffle_factor", info.pseudonym.s.scalar().to_hex());
            out.value("pseudonym_rekey_factor", info.pseudonym.k.scalar().to_hex());
            out.value("attribute_rekey_factor", info.attribute.k.scalar().to_hex());
        }
        Factors::Commitments(transition) => {
            let commitment = VerifiableTranscryptionCommitment::from(transition.info()?);
            let pseudonym = commitment.pseudonym;
            out.value(
                "reshuffle_commitment",
                pseudonym.reshuffle_commitment.point().to_hex(),
            );
            out.value(
                "pseudonym_rekey_commitment",
                pseudonym.rekey_commitment.point().to_hex(),
            );
            out.value(
                "attribute_rekey_commitment",
                commitment.attribute.commitment.point().to_hex(),
            );
        }
    }
    Ok(())
}
