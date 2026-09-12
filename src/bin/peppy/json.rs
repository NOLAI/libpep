//! `peppy json`: JSON documents with nested pseudonyms and attributes.
//!
//! Session keys are given as the JSON object that `peppy keys session derive --json` prints,
//! typically via `--keys @session.json`.

use crate::io::{self, Output, Result};
use clap::Subcommand;
use libpep::data::json::{EncryptedPEPJSONValue, PEPJSONBuilder};
use libpep::data::traits::{Encryptable, Encrypted, Transcryptable};
use libpep::factors::TranscryptionInfo;
use libpep::keys::{GlobalPublicKeys, SessionKeys};
use rand_core::{CryptoRng, Rng};

#[derive(Subcommand)]
pub enum Json {
    /// Encrypt a JSON document; the named fields are encrypted as pseudonyms, the rest as
    /// attributes.
    Encrypt {
        /// Session keys as JSON (from `keys session derive --json`), or global public keys as
        /// JSON with --global.
        #[arg(long)]
        keys: String,
        /// Encrypt with global public keys instead of session keys.
        #[arg(long)]
        global: bool,
        /// A field whose value is a pseudonym; repeat for several fields.
        #[arg(long = "pseudonym-field")]
        pseudonym_fields: Vec<String>,
        /// The JSON document.
        value: String,
    },
    /// Decrypt an encrypted JSON document with session keys.
    Decrypt {
        /// Session keys as JSON (from `keys session derive --json`).
        #[arg(long)]
        keys: String,
        /// The encrypted JSON document.
        value: String,
    },
    /// Transcrypt an encrypted JSON document from one domain and session to another.
    Transcrypt {
        /// The session keys the document is encrypted under, as JSON, needed to rerandomize
        /// its pseudonyms.
        #[cfg(not(feature = "elgamal3"))]
        #[arg(long)]
        keys: String,
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
        /// The encrypted JSON document.
        value: String,
    },
}

/// Parse a keys object, accepting either the object itself or a `--json` output that has it
/// under `key`.
fn keys_json<T: serde::de::DeserializeOwned>(raw: &str, key: &str, what: &str) -> Result<T> {
    let text = io::read_arg(raw)?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| io::Error::input(format!("{what}: not valid JSON: {e}")))?;
    if let Some(inner) = value.get_mut(key) {
        value = inner.take();
    }
    serde_json::from_value(value).map_err(|e| io::Error::input(format!("{what}: {e}")))
}

fn document(raw: &str) -> Result<serde_json::Value> {
    let text = io::read_arg(raw)?;
    serde_json::from_str(&text).map_err(|e| io::Error::input(format!("value: not valid JSON: {e}")))
}

pub fn run<R: Rng + CryptoRng>(cmd: Json, rng: &mut R, out: &mut Output) -> Result<()> {
    match cmd {
        Json::Encrypt {
            keys,
            global,
            pseudonym_fields,
            value,
        } => {
            let fields: Vec<&str> = pseudonym_fields.iter().map(String::as_str).collect();
            let document = PEPJSONBuilder::from_json(&document(&value)?, &fields)
                .ok_or_else(|| io::Error::input("value: a pseudonym field must hold a string"))?
                .build();
            let encrypted = if global {
                let keys: GlobalPublicKeys = keys_json(&keys, "global_public_keys", "keys")?;
                document.encrypt_global(&keys, rng)
            } else {
                let keys: SessionKeys = keys_json(&keys, "session_keys", "keys")?;
                document.encrypt(&keys, rng)
            };
            out.value(
                "encrypted",
                serde_json::to_value(&encrypted).expect("encrypted JSON is serializable"),
            );
        }
        Json::Decrypt { keys, value } => {
            let keys: SessionKeys = keys_json(&keys, "session_keys", "keys")?;
            let encrypted: EncryptedPEPJSONValue = serde_json::from_value(document(&value)?)
                .map_err(|e| io::Error::input(format!("value: not an encrypted document: {e}")))?;
            #[cfg(feature = "elgamal3")]
            let decrypted = encrypted
                .decrypt(&keys)
                .ok_or_else(io::Error::key_mismatch)?;
            #[cfg(not(feature = "elgamal3"))]
            let decrypted = encrypted.decrypt(&keys);
            let json = decrypted.to_value().map_err(|e| {
                io::Error::input(format!("the document does not decode to JSON: {e}"))
            })?;
            out.value("document", json);
        }
        Json::Transcrypt {
            #[cfg(not(feature = "elgamal3"))]
            keys,
            pseudonymization_secret,
            encryption_secret,
            from_domain,
            to_domain,
            from_context,
            to_context,
            value,
        } => {
            let info = TranscryptionInfo::new(
                &io::domain(&from_domain)?,
                &io::domain(&to_domain)?,
                &io::context(from_context.as_deref())?,
                &io::context(to_context.as_deref())?,
                &io::pseudonymization_secret(&pseudonymization_secret)?,
                &io::encryption_secret(&encryption_secret)?,
            );
            let encrypted: EncryptedPEPJSONValue = serde_json::from_value(document(&value)?)
                .map_err(|e| io::Error::input(format!("value: not an encrypted document: {e}")))?;
            #[cfg(feature = "elgamal3")]
            let transcrypted = encrypted.transcrypt(&info, rng);
            #[cfg(not(feature = "elgamal3"))]
            let transcrypted = {
                let keys: SessionKeys = keys_json(&keys, "session_keys", "keys")?;
                encrypted.transcrypt(&info, &keys, rng)
            };
            out.value(
                "encrypted",
                serde_json::to_value(transcrypted).expect("encrypted JSON is serializable"),
            );
        }
    }
    Ok(())
}
