//! `peppy factors`: derive reshuffle and rekey factors from secrets, and the info for a
//! transcryption between two domains and contexts.

use crate::io::{self, Output, Result};
use clap::Subcommand;
use libpep::elgamal::arithmetic::scalars::ScalarTraits;
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
    RekeyFactor, TranscryptionInfo,
};

#[derive(Subcommand)]
pub enum Factors {
    /// The reshuffle factor of a pseudonymization domain.
    Reshuffle {
        /// The transcryptor's pseudonymization secret.
        #[arg(long)]
        secret: String,
        /// The pseudonymization domain.
        #[arg(long)]
        domain: String,
    },
    /// The rekey factor of an encryption context.
    Rekey {
        /// The transcryptor's encryption secret.
        #[arg(long)]
        secret: String,
        /// The encryption context (session); omit for the global context.
        #[arg(long)]
        context: Option<String>,
        /// The attribute rekey factor instead of the pseudonym rekey factor.
        #[arg(long)]
        attribute: bool,
    },
    /// The factors that transcrypt from one domain and context to another: the ratios of the
    /// reshuffle and rekey factors of source and target.
    Info {
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
    },
}

pub fn run(cmd: Factors, out: &mut Output) -> Result<()> {
    match cmd {
        Factors::Reshuffle { secret, domain } => {
            let factor = make_pseudonymisation_factor(
                &io::pseudonymization_secret(&secret)?,
                &io::domain(&domain)?,
            );
            out.value("reshuffle_factor", factor.scalar().to_hex());
        }
        Factors::Rekey {
            secret,
            context,
            attribute,
        } => {
            let secret = io::encryption_secret(&secret)?;
            let context = io::context(context.as_deref())?;
            let factor = if attribute {
                make_attribute_rekey_factor(&secret, &context).scalar()
            } else {
                make_pseudonym_rekey_factor(&secret, &context).scalar()
            };
            out.value("rekey_factor", factor.to_hex());
        }
        Factors::Info {
            pseudonymization_secret,
            encryption_secret,
            from_domain,
            to_domain,
            from_context,
            to_context,
        } => {
            let info = TranscryptionInfo::new(
                &io::domain(&from_domain)?,
                &io::domain(&to_domain)?,
                &io::context(from_context.as_deref())?,
                &io::context(to_context.as_deref())?,
                &io::pseudonymization_secret(&pseudonymization_secret)?,
                &io::encryption_secret(&encryption_secret)?,
            );
            out.value("reshuffle_factor", info.pseudonym.s.scalar().to_hex());
            out.value("pseudonym_rekey_factor", info.pseudonym.k.scalar().to_hex());
            out.value("attribute_rekey_factor", info.attribute.k.scalar().to_hex());
        }
    }
    Ok(())
}
