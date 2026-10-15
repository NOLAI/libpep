//! Input parsing and output formatting shared by all subcommands.
//!
//! Every value argument may be given literally, as `-` to read it from standard input, or as
//! `@path` to read it from a file. Values are printed one per line on standard output, with a
//! label when standard output is a terminal and bare when it is piped; with `--json` all values
//! of a command are printed as one JSON object instead.

use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::elgamal::arithmetic::group_elements::GroupElement;
use libpep::elgamal::arithmetic::scalars::ScalarNonZero;
use libpep::elgamal::arithmetic::Ristretto255;
use libpep::elgamal::verifiable::generic::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
};
use libpep::elgamal::ElGamal;
#[cfg(feature = "json")]
use libpep::factors::commitments::VerifiableTranscryptionCommitment;
use libpep::factors::commitments::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
};
use libpep::factors::derivation::MAX_INPUT_LENGTH;
use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::keys::{PublicKey, SecretKey};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt;
use std::io::{IsTerminal, Read};

/// Exit code for malformed input.
pub const EXIT_INPUT: i32 = 1;
/// Exit code for a decryption with a key that does not match the ciphertext. Only reachable
/// with the `elgamal3` feature, where ciphertexts carry the key they were encrypted for.
/// (clap exits with 2 on a usage error, so the codes start at 3.)
#[cfg_attr(not(feature = "elgamal3"), allow(dead_code))]
pub const EXIT_KEY_MISMATCH: i32 = 3;
/// Exit code for a proof that does not verify.
pub const EXIT_INVALID_PROOF: i32 = 4;

/// A failure reported to the user with an exit code.
#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub code: i32,
}

impl Error {
    pub fn input(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: EXIT_INPUT,
        }
    }

    #[cfg_attr(not(feature = "elgamal3"), allow(dead_code))]
    pub fn key_mismatch() -> Self {
        Self {
            message: "decryption failed: the key does not match the ciphertext".into(),
            code: EXIT_KEY_MISMATCH,
        }
    }

    pub fn invalid_proof() -> Self {
        Self {
            message: "the proof does not verify against the ciphertext and the commitments".into(),
            code: EXIT_INVALID_PROOF,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::input(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Resolve a value argument: `-` reads standard input, `@path` reads a file, anything else is
/// the value itself. Surrounding whitespace is trimmed for the first two.
pub fn read_arg(raw: &str) -> Result<String> {
    if raw == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf.trim().to_string())
    } else if let Some(path) = raw.strip_prefix('@') {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::input(format!("cannot read {path}: {e}")))?;
        Ok(text.trim().to_string())
    } else {
        Ok(raw.to_string())
    }
}

/// Resolve a list of value arguments; a single argument may expand to several values when it
/// contains whitespace (long values are given as space-separated blocks).
pub fn read_values(raw: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for r in raw {
        let v = read_arg(r)?;
        out.extend(v.split_whitespace().map(str::to_string));
    }
    if out.is_empty() {
        return Err(Error::input("no value given"));
    }
    Ok(out)
}

pub fn scalar(raw: &str, what: &str) -> Result<ScalarNonZero> {
    let s = read_arg(raw)?;
    ScalarNonZero::from_hex(&s).ok_or_else(|| {
        Error::input(format!(
            "{what}: expected a non-zero scalar as 64 hex digits"
        ))
    })
}

pub fn point(raw: &str, what: &str) -> Result<GroupElement> {
    let s = read_arg(raw)?;
    GroupElement::from_hex(&s)
        .ok_or_else(|| Error::input(format!("{what}: expected a group element as 64 hex digits")))
}

pub fn ciphertext(raw: &str) -> Result<ElGamal> {
    let s = read_arg(raw)?;
    ElGamal::from_base64(&s)
        .ok_or_else(|| Error::input("ciphertext: expected a base64-encoded ElGamal ciphertext"))
}

pub fn public_key<K: PublicKey>(raw: &str, what: &str) -> Result<K> {
    let s = read_arg(raw)?;
    K::from_hex(&s)
        .ok_or_else(|| Error::input(format!("{what}: expected a public key as 64 hex digits")))
}

pub fn secret_key<K: SecretKey<Group = Ristretto255>>(raw: &str, what: &str) -> Result<K> {
    Ok(K::from_scalar(scalar(raw, what)?))
}

/// A secret, domain or context: the factor derivation needs it shorter than 2^16 bytes.
fn derivation_input(raw: &str, what: &str) -> Result<String> {
    let text = read_arg(raw)?;
    if text.len() >= MAX_INPUT_LENGTH {
        return Err(Error::input(format!(
            "{what}: must be shorter than {MAX_INPUT_LENGTH} bytes"
        )));
    }
    Ok(text)
}

pub fn pseudonymization_secret(raw: &str) -> Result<PseudonymizationSecret> {
    Ok(PseudonymizationSecret::from(
        derivation_input(raw, "pseudonymization secret")?.into_bytes(),
    ))
}

pub fn encryption_secret(raw: &str) -> Result<EncryptionSecret> {
    Ok(EncryptionSecret::from(
        derivation_input(raw, "encryption secret")?.into_bytes(),
    ))
}

pub fn domain(raw: &str) -> Result<PseudonymizationDomain> {
    Ok(PseudonymizationDomain::from(
        derivation_input(raw, "domain")?.as_str(),
    ))
}

/// An encryption context; `None` is the global context, for data encrypted towards a global key.
pub fn context(raw: Option<&str>) -> Result<EncryptionContext> {
    match raw {
        Some(r) => Ok(EncryptionContext::from(
            derivation_input(r, "context")?.as_str(),
        )),
        None => Ok(EncryptionContext::global()),
    }
}

pub fn rekey_commitment(raw: &str) -> Result<VerifiableRekeyCommitment> {
    Ok(VerifiableRekeyCommitment {
        commitment: RekeyFactorCommitment(FactorCommitment(point(raw, "rekey commitment")?)),
    })
}

pub fn pseudonymization_commitment(
    reshuffle: &str,
    rekey: &str,
) -> Result<VerifiablePseudonymizationCommitment> {
    Ok(VerifiablePseudonymizationCommitment {
        reshuffle_commitment: PseudonymizationFactorCommitment(FactorCommitment(point(
            reshuffle,
            "reshuffle commitment",
        )?)),
        rekey_commitment: rekey_commitment(rekey)?.commitment,
    })
}

#[cfg(feature = "json")]
pub fn transcryption_commitment(
    reshuffle: &str,
    pseudonym_rekey: &str,
    attribute_rekey: &str,
) -> Result<VerifiableTranscryptionCommitment> {
    Ok(VerifiableTranscryptionCommitment {
        pseudonym: pseudonymization_commitment(reshuffle, pseudonym_rekey)?,
        attribute: rekey_commitment(attribute_rekey)?,
    })
}

/// Parse a JSON value, such as a proof or an encrypted document.
pub fn json<T: DeserializeOwned>(raw: &str, what: &str) -> Result<T> {
    let text = read_arg(raw)?;
    serde_json::from_str(&text).map_err(|e| Error::input(format!("{what}: not valid JSON: {e}")))
}

/// The JSON value of a proof, key or document, for [`Output::value`].
pub fn to_json<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).expect("library types are serializable")
}

/// Collects the values a command outputs and prints them in the selected format.
pub struct Output {
    json: bool,
    fields: Vec<(String, serde_json::Value)>,
}

impl Output {
    pub fn new(json: bool) -> Self {
        Self {
            json,
            fields: Vec::new(),
        }
    }

    /// Whether output is collected as JSON.
    #[cfg_attr(not(feature = "json"), allow(dead_code))]
    pub fn json(&self) -> bool {
        self.json
    }

    /// Emit one value under a snake_case key. In line mode the value is printed on standard
    /// output, labelled when that is a terminal and bare when it is piped.
    pub fn value(&mut self, key: &str, value: impl Into<serde_json::Value>) {
        let value = value.into();
        if !self.json {
            let rendered = match &value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(items) => items
                    .iter()
                    .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
                    .collect::<Vec<_>>()
                    .join(" "),
                other => other.to_string(),
            };
            if std::io::stdout().is_terminal() {
                println!("{}: {rendered}", key.replace('_', " "));
            } else {
                println!("{rendered}");
            }
        }
        self.fields.push((key.to_string(), value));
    }

    /// Emit a note for the user that is not part of the output values.
    pub fn note(&self, message: &str) {
        eprintln!("{message}");
    }

    pub fn finish(self) {
        if self.json {
            let object: serde_json::Map<String, serde_json::Value> =
                self.fields.into_iter().collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(object))
                    .expect("output values are serializable")
            );
        }
    }
}
