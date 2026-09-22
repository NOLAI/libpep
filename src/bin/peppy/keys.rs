//! `peppy keys`: global, session and distributed key material.

use crate::io::{self, Output, Result};
use clap::Subcommand;
use libpep::client::distributed::{
    make_session_keys_distributed, update_attribute_session_key, update_pseudonym_session_key,
};
use libpep::elgamal::arithmetic::scalars::ScalarTraits;
use libpep::factors::{make_attribute_rekey_factor, make_pseudonym_rekey_factor};
use libpep::keys::distribution::{
    make_distributed_global_keys, make_session_key_shares, AttributeSessionKeyShare,
    BlindedAttributeGlobalSecretKey, BlindedGlobalSecretKey, BlindedGlobalSecretKeys,
    BlindedPseudonymGlobalSecretKey, BlindingFactor, PseudonymSessionKeyShare, SessionKeyShare,
    SessionKeyShares,
};
#[cfg(feature = "json")]
use libpep::keys::SessionKeys;
use libpep::keys::{
    make_attribute_session_keys, make_global_keys, make_pseudonym_session_keys,
    AttributeGlobalSecretKey, AttributeSessionKeys, AttributeSessionSecretKey,
    PseudonymGlobalSecretKey, PseudonymSessionKeys, PseudonymSessionSecretKey, PublicKey,
    SecretKey,
};
use rand_core::{CryptoRng, Rng};

#[derive(Subcommand)]
pub enum Keys {
    /// Global keys, generated once per system.
    #[command(subcommand)]
    Global(Global),
    /// Session keys, derived from global keys for one encryption context.
    #[command(subcommand)]
    Session(Session),
    /// Keys for a system with n transcryptors that never hold the global secret key.
    #[command(subcommand)]
    Distributed(Distributed),
}

#[derive(Subcommand)]
pub enum Global {
    /// Generate a global key pair for pseudonyms and one for attributes.
    Generate,
}

#[derive(Subcommand)]
pub enum Session {
    /// Derive session keys from global secret keys, an encryption secret and a context.
    Derive {
        /// Global secret key for pseudonyms (hex).
        #[arg(long)]
        pseudonym_global_secret: Option<String>,
        /// Global secret key for attributes (hex).
        #[arg(long)]
        attribute_global_secret: Option<String>,
        /// The transcryptor's encryption secret.
        #[arg(long)]
        secret: String,
        /// The encryption context (session) to derive keys for.
        #[arg(long)]
        context: String,
    },
}

#[derive(Subcommand)]
pub enum Distributed {
    /// Generate global keys, blind the secret keys, and produce one blinding factor per
    /// transcryptor. The blinded keys are public; each blinding factor goes to one transcryptor.
    Setup {
        /// Number of transcryptors.
        #[arg(short, long)]
        n: usize,
    },
    /// A transcryptor's session key shares for a context, from its blinding factor.
    Share {
        /// This transcryptor's blinding factor (hex).
        #[arg(long)]
        blinding: String,
        /// This transcryptor's encryption secret.
        #[arg(long)]
        secret: String,
        /// The encryption context (session).
        #[arg(long)]
        context: String,
    },
    /// Reconstruct session keys from a blinded global key and one share per transcryptor.
    Reconstruct {
        /// Blinded global secret key for pseudonyms (hex).
        #[arg(long)]
        blinded_pseudonym: Option<String>,
        /// Blinded global secret key for attributes (hex).
        #[arg(long)]
        blinded_attribute: Option<String>,
        /// Pseudonym session key share, once per transcryptor (hex).
        #[arg(long = "pseudonym-share")]
        pseudonym_shares: Vec<String>,
        /// Attribute session key share, once per transcryptor (hex).
        #[arg(long = "attribute-share")]
        attribute_shares: Vec<String>,
    },
    /// Replace one transcryptor's share in a session key, moving it to another context.
    Update {
        /// The current session secret key (hex).
        #[arg(long)]
        secret_key: String,
        /// The share of the transcryptor for the current context (hex).
        #[arg(long)]
        old_share: String,
        /// The share of the same transcryptor for the new context (hex).
        #[arg(long)]
        new_share: String,
        /// The key is an attribute session key instead of a pseudonym session key.
        #[arg(long)]
        attribute: bool,
    },
}

pub fn run<R: Rng + CryptoRng>(cmd: Keys, rng: &mut R, out: &mut Output) -> Result<()> {
    match cmd {
        Keys::Global(Global::Generate) => {
            let (public, secret) = make_global_keys(rng);
            out.value("pseudonym_public_key", public.pseudonym.to_hex());
            out.value("pseudonym_secret_key", secret.pseudonym.value().to_hex());
            out.value("attribute_public_key", public.attribute.to_hex());
            out.value("attribute_secret_key", secret.attribute.value().to_hex());
            #[cfg(feature = "json")]
            if out.json() {
                out.value(
                    "global_public_keys",
                    serde_json::to_value(public).expect("keys are serializable"),
                );
            }
        }
        Keys::Session(Session::Derive {
            pseudonym_global_secret,
            attribute_global_secret,
            secret,
            context,
        }) => {
            if pseudonym_global_secret.is_none() && attribute_global_secret.is_none() {
                return Err(io::Error::input(
                    "give --pseudonym-global-secret, --attribute-global-secret or both",
                ));
            }
            let secret = io::encryption_secret(&secret)?;
            let context = io::context(Some(&context))?;
            let mut pseudonym = None;
            if let Some(global) = pseudonym_global_secret {
                let global: PseudonymGlobalSecretKey =
                    io::secret_key(&global, "pseudonym global secret key")?;
                let (public, secret) = make_pseudonym_session_keys(&global, &context, &secret);
                out.value("pseudonym_public_key", public.to_hex());
                out.value("pseudonym_secret_key", secret.value().to_hex());
                pseudonym = Some(PseudonymSessionKeys { public, secret });
            }
            let mut attribute = None;
            if let Some(global) = attribute_global_secret {
                let global: AttributeGlobalSecretKey =
                    io::secret_key(&global, "attribute global secret key")?;
                let (public, secret) = make_attribute_session_keys(&global, &context, &secret);
                out.value("attribute_public_key", public.to_hex());
                out.value("attribute_secret_key", secret.value().to_hex());
                attribute = Some(AttributeSessionKeys { public, secret });
            }
            #[cfg(feature = "json")]
            if let (true, Some(pseudonym), Some(attribute)) = (out.json(), pseudonym, attribute) {
                out.value(
                    "session_keys",
                    serde_json::to_value(SessionKeys {
                        pseudonym,
                        attribute,
                    })
                    .expect("keys are serializable"),
                );
            }
            #[cfg(not(feature = "json"))]
            let _ = (pseudonym, attribute);
        }
        Keys::Distributed(Distributed::Setup { n }) => {
            if n == 0 {
                return Err(io::Error::input(
                    "a distributed system needs at least one transcryptor",
                ));
            }
            let (public, blinded, factors) = make_distributed_global_keys(n, rng);
            out.value("pseudonym_public_key", public.pseudonym.to_hex());
            out.value("attribute_public_key", public.attribute.to_hex());
            out.value("blinded_pseudonym_secret_key", blinded.pseudonym.to_hex());
            out.value("blinded_attribute_secret_key", blinded.attribute.to_hex());
            out.value(
                "blinding_factors",
                factors.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
            );
            out.note("Keep each blinding factor secret and hand it to one transcryptor.");
        }
        Keys::Distributed(Distributed::Share {
            blinding,
            secret,
            context,
        }) => {
            let blinding = BlindingFactor::from_scalar(io::scalar(&blinding, "blinding factor")?);
            let secret = io::encryption_secret(&secret)?;
            let context = io::context(Some(&context))?;
            let shares = make_session_key_shares(
                &make_pseudonym_rekey_factor(&secret, &context),
                &make_attribute_rekey_factor(&secret, &context),
                &blinding,
            );
            out.value("pseudonym_share", shares.pseudonym.to_hex());
            out.value("attribute_share", shares.attribute.to_hex());
        }
        Keys::Distributed(Distributed::Reconstruct {
            blinded_pseudonym,
            blinded_attribute,
            pseudonym_shares,
            attribute_shares,
        }) => match (blinded_pseudonym, blinded_attribute) {
            (Some(bp), Some(ba)) if pseudonym_shares.len() == attribute_shares.len() => {
                let blinded = BlindedGlobalSecretKeys {
                    pseudonym: BlindedPseudonymGlobalSecretKey::from_scalar(io::scalar(
                        &bp,
                        "blinded pseudonym secret key",
                    )?),
                    attribute: BlindedAttributeGlobalSecretKey::from_scalar(io::scalar(
                        &ba,
                        "blinded attribute secret key",
                    )?),
                };
                let shares = pseudonym_shares
                    .iter()
                    .zip(&attribute_shares)
                    .map(|(p, a)| {
                        Ok(SessionKeyShares {
                            pseudonym: share(p, "pseudonym share")?,
                            attribute: share(a, "attribute share")?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let keys = make_session_keys_distributed(blinded, &shares);
                out.value("pseudonym_public_key", keys.pseudonym.public.to_hex());
                out.value(
                    "pseudonym_secret_key",
                    keys.pseudonym.secret.value().to_hex(),
                );
                out.value("attribute_public_key", keys.attribute.public.to_hex());
                out.value(
                    "attribute_secret_key",
                    keys.attribute.secret.value().to_hex(),
                );
                #[cfg(feature = "json")]
                if out.json() {
                    out.value(
                        "session_keys",
                        serde_json::to_value(keys).expect("keys are serializable"),
                    );
                }
            }
            (Some(_), Some(_)) => {
                return Err(io::Error::input(
                    "give the same number of --pseudonym-share and --attribute-share values",
                ))
            }
            (Some(bp), None) => {
                let blinded = BlindedPseudonymGlobalSecretKey::from_scalar(io::scalar(
                    &bp,
                    "blinded pseudonym secret key",
                )?);
                let shares = pseudonym_shares
                    .iter()
                    .map(|p| share::<PseudonymSessionKeyShare>(p, "pseudonym share"))
                    .collect::<Result<Vec<_>>>()?;
                let (public, secret) =
                    libpep::client::distributed::make_pseudonym_session_key(blinded, &shares);
                out.value("pseudonym_public_key", public.to_hex());
                out.value("pseudonym_secret_key", secret.value().to_hex());
            }
            (None, Some(ba)) => {
                let blinded = BlindedAttributeGlobalSecretKey::from_scalar(io::scalar(
                    &ba,
                    "blinded attribute secret key",
                )?);
                let shares = attribute_shares
                    .iter()
                    .map(|a| share::<AttributeSessionKeyShare>(a, "attribute share"))
                    .collect::<Result<Vec<_>>>()?;
                let (public, secret) =
                    libpep::client::distributed::make_attribute_session_key(blinded, &shares);
                out.value("attribute_public_key", public.to_hex());
                out.value("attribute_secret_key", secret.value().to_hex());
            }
            (None, None) => {
                return Err(io::Error::input(
                    "give --blinded-pseudonym, --blinded-attribute or both",
                ))
            }
        },
        Keys::Distributed(Distributed::Update {
            secret_key,
            old_share,
            new_share,
            attribute,
        }) => {
            if attribute {
                let key: AttributeSessionSecretKey =
                    io::secret_key(&secret_key, "attribute session secret key")?;
                let (public, secret) = update_attribute_session_key(
                    key,
                    share(&old_share, "old share")?,
                    share(&new_share, "new share")?,
                );
                out.value("attribute_public_key", public.to_hex());
                out.value("attribute_secret_key", secret.value().to_hex());
            } else {
                let key: PseudonymSessionSecretKey =
                    io::secret_key(&secret_key, "pseudonym session secret key")?;
                let (public, secret) = update_pseudonym_session_key(
                    key,
                    share(&old_share, "old share")?,
                    share(&new_share, "new share")?,
                );
                out.value("pseudonym_public_key", public.to_hex());
                out.value("pseudonym_secret_key", secret.value().to_hex());
            }
        }
    }
    Ok(())
}

fn share<S: SessionKeyShare>(raw: &str, what: &str) -> Result<S> {
    Ok(S::from_scalar(io::scalar(raw, what)?))
}
