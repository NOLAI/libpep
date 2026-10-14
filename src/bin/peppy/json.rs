//! `peppy json`: JSON documents with nested pseudonyms and attributes.
//!
//! Session keys are given as the JSON object that `peppy keys session derive --json` prints,
//! typically via `--keys @session.json`.

use crate::io::{self, Output, Result};
use clap::Subcommand;
use libpep::data::json::{EncryptedPepJsonValue, PepJsonBuilder};
use libpep::data::traits::{Encryptable, Encrypted, Transcryptable};
use libpep::data::verifiable::json::JsonTranscryptionProof;
use libpep::data::verifiable::traits::{VerifiableTranscryptable, VerifiableTranscryptionProof};
use libpep::factors::commitments::VerifiableTranscryptionCommitment;
#[cfg(not(feature = "elgamal3"))]
use libpep::factors::RekeyPublicKey;
use libpep::factors::TranscryptionInfo;
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::SessionPublicKeys;
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
        /// The session public keys the document is encrypted under, as JSON (from
        /// `keys session derive --json`; the secret keys are ignored).
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
        /// Also output a proof of the transcryption, to be verified against the transcryptor's
        /// commitments.
        #[arg(long)]
        prove: bool,
        /// The encrypted JSON document.
        value: String,
    },
    /// Verify the proof of a transcryption against the transcryptor's commitments and output
    /// the transcrypted document.
    VerifyTranscrypt {
        /// The session public keys the original document is encrypted under, as JSON (from
        /// `keys session derive --json`; the secret keys are ignored).
        #[cfg(not(feature = "elgamal3"))]
        #[arg(long)]
        keys: String,
        /// The transcryptor's commitment to the reshuffle factor (hex).
        #[arg(long)]
        reshuffle_commitment: String,
        /// The transcryptor's commitment to the pseudonym rekey factor (hex).
        #[arg(long)]
        pseudonym_rekey_commitment: String,
        /// The transcryptor's commitment to the attribute rekey factor (hex).
        #[arg(long)]
        attribute_rekey_commitment: String,
        /// The proof (JSON) the transcryptor produced with --prove.
        #[arg(long)]
        proof: String,
        /// The original encrypted JSON document.
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

/// Parse session public keys from either a `SessionPublicKeys` object or a `SessionKeys` object
/// (as printed by `keys session derive --json`), whose secret keys are ignored.
#[cfg(not(feature = "elgamal3"))]
fn public_keys_json(raw: &str) -> Result<SessionPublicKeys> {
    let text = io::read_arg(raw)?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| io::Error::input(format!("keys: not valid JSON: {e}")))?;
    if let Some(inner) = value.get_mut("session_keys") {
        value = inner.take();
    }
    if let Ok(keys) = serde_json::from_value::<SessionKeys>(value.clone()) {
        return Ok(keys.public());
    }
    serde_json::from_value(value).map_err(|e| io::Error::input(format!("keys: {e}")))
}

fn document(raw: &str) -> Result<serde_json::Value> {
    io::json(raw, "value")
}

fn encrypted_document(raw: &str) -> Result<EncryptedPepJsonValue> {
    serde_json::from_value(document(raw)?)
        .map_err(|e| io::Error::input(format!("value: not an encrypted document: {e}")))
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
            let document = PepJsonBuilder::from_json(&document(&value)?, &fields)
                .ok_or_else(|| io::Error::input("value: a pseudonym field must hold a string"))?
                .build();
            let encrypted = if global {
                let keys: GlobalPublicKeys = keys_json(&keys, "global_public_keys", "keys")?;
                document.encrypt_global(&keys, rng)
            } else {
                let keys: SessionKeys = keys_json(&keys, "session_keys", "keys")?;
                document.encrypt(&keys.public(), rng)
            };
            out.value("encrypted", io::to_json(&encrypted));
        }
        Json::Decrypt { keys, value } => {
            let keys: SessionKeys = keys_json(&keys, "session_keys", "keys")?;
            let encrypted = encrypted_document(&value)?;
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
            prove,
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
            let encrypted = encrypted_document(&value)?;
            #[cfg(not(feature = "elgamal3"))]
            let keys: SessionPublicKeys = public_keys_json(&keys)?;
            if prove {
                #[cfg(feature = "elgamal3")]
                let proof = encrypted.verifiable_transcrypt(&info, rng);
                #[cfg(not(feature = "elgamal3"))]
                let proof = encrypted.verifiable_transcrypt(&info, &keys, rng);
                let commitment = VerifiableTranscryptionCommitment::from(info);
                #[cfg(feature = "elgamal3")]
                let transcrypted = proof.verified_reconstruct(&encrypted, &commitment);
                #[cfg(not(feature = "elgamal3"))]
                let transcrypted = proof.verified_reconstruct(&encrypted, &keys, &commitment);
                let transcrypted =
                    transcrypted.expect("a fresh proof verifies against its own commitments");
                out.value("encrypted", io::to_json(&transcrypted));
                out.value("proof", io::to_json(&proof));
            } else {
                #[cfg(feature = "elgamal3")]
                let transcrypted = encrypted.transcrypt(&info, rng);
                #[cfg(not(feature = "elgamal3"))]
                let transcrypted = encrypted.transcrypt(&info, &keys, rng);
                out.value("encrypted", io::to_json(&transcrypted));
            }
            #[cfg(not(feature = "elgamal3"))]
            out.value("keys", io::to_json(&info.rekey_public_key(&keys)));
        }
        Json::VerifyTranscrypt {
            #[cfg(not(feature = "elgamal3"))]
            keys,
            reshuffle_commitment,
            pseudonym_rekey_commitment,
            attribute_rekey_commitment,
            proof,
            value,
        } => {
            let commitment = io::transcryption_commitment(
                &reshuffle_commitment,
                &pseudonym_rekey_commitment,
                &attribute_rekey_commitment,
            )?;
            let original = encrypted_document(&value)?;
            let proof: JsonTranscryptionProof = io::json(&proof, "proof")?;
            #[cfg(feature = "elgamal3")]
            let transcrypted = proof.verified_reconstruct(&original, &commitment);
            #[cfg(not(feature = "elgamal3"))]
            let transcrypted = {
                let keys: SessionPublicKeys = public_keys_json(&keys)?;
                proof.verified_reconstruct(&original, &keys, &commitment)
            };
            out.value(
                "encrypted",
                io::to_json(&transcrypted.ok_or_else(io::Error::invalid_proof)?),
            );
        }
    }
    Ok(())
}
