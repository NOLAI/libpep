//! `peppy pseudonym` and `peppy attribute`: encoding, encryption, decryption and transcryption
//! of the two data types, short or long.
//!
//! The two commands share one implementation through [`Kind`], which names the plain, encrypted,
//! long and key types of each. A value with more than one block is treated as a long value:
//! plain blocks are space-separated hex, encrypted blocks are `|`-separated base64.
//!
//! The transcryption commands take `--prove` to also produce a proof of the operation; the
//! `verify-*` commands check such a proof, see [`crate::verifiable`].

use crate::factors::{AttributeTransitionArgs, TransitionArgs};
use crate::io::{self, Output, Result};
use crate::verifiable::{self, VerifyPseudonymizeArgs, VerifyRekeyArgs};
use clap::{Args, Subcommand};
use libpep::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use libpep::data::padding::{Padded, PaddingError};
use libpep::data::simple::{
    Attribute, ElGamalEncryptable, ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym,
    Pseudonym,
};
use libpep::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use libpep::data::verifiable::traits::{VerifiableRekeyProof, VerifiableRekeyable};
use libpep::elgamal::arithmetic::scalars::ScalarNonZero;
use libpep::elgamal::arithmetic::Ristretto255;
use libpep::errors::ParseError;
use libpep::factors::commitments::VerifiableRekeyCommitment;
use libpep::factors::{
    AttributeRekeyFactor, AttributeRekeyInfo, PseudonymRekeyFactor, PseudonymRekeyInfo,
    PseudonymizationInfo, RekeyPublicKey, ReshuffleFactor,
};
use libpep::keys::{
    AttributeGlobalPublicKey, AttributeSessionPublicKey, AttributeSessionSecretKey,
    PseudonymGlobalPublicKey, PseudonymSessionPublicKey, PseudonymSessionSecretKey, PublicKey,
    SecretKey,
};
#[cfg(feature = "insecure")]
use libpep::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use rand_core::{CryptoRng, Rng};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// The length of one block (a group element) in hex digits.
const HEX_BLOCK: usize = 64;

#[derive(Subcommand)]
pub enum PseudonymCommand {
    /// A random pseudonym.
    Random,
    /// Encode an identifier as a pseudonym; identifiers over 15 bytes become long pseudonyms.
    Encode(EncodeArgs),
    /// Decode a pseudonym back to the identifier it encodes.
    Decode(DecodeArgs),
    /// Encrypt a pseudonym with a session public key, or a global public key with --global.
    Encrypt(EncryptArgs),
    /// Decrypt an encrypted pseudonym with a session secret key.
    Decrypt(DecryptArgs),
    /// Rerandomize an encrypted pseudonym.
    Rerandomize(RerandomizeArgs),
    /// Rekey an encrypted pseudonym to another session with a rekey factor.
    Rekey(RekeyArgs),
    /// Pseudonymize an encrypted pseudonym to another domain and session with explicit factors.
    Pseudonymize(PseudonymizeArgs),
    /// Transcrypt an encrypted pseudonym from one domain and session to another, as a
    /// transcryptor with the given secrets.
    Transcrypt(TranscryptArgs),
    /// Verify the proof of a rekeying against the transcryptor's commitment and output the
    /// rekeyed ciphertext.
    VerifyRekey(VerifyRekeyArgs),
    /// Verify the proof of a pseudonymization or transcryption against the transcryptor's
    /// commitments and output the pseudonymized ciphertext.
    VerifyPseudonymize(VerifyPseudonymizeArgs),
}

#[derive(Subcommand)]
pub enum AttributeCommand {
    /// A random attribute.
    Random,
    /// Encode a value as an attribute; values over 15 bytes become long attributes.
    Encode(EncodeArgs),
    /// Decode an attribute back to the value it encodes.
    Decode(DecodeArgs),
    /// Encrypt an attribute with a session public key, or a global public key with --global.
    Encrypt(EncryptArgs),
    /// Decrypt an encrypted attribute with a session secret key.
    Decrypt(DecryptArgs),
    /// Rerandomize an encrypted attribute.
    Rerandomize(RerandomizeArgs),
    /// Rekey an encrypted attribute to another session with a rekey factor.
    Rekey(RekeyArgs),
    /// Transcrypt an encrypted attribute from one session to another, as a transcryptor with the
    /// given secret.
    Transcrypt(AttributeTranscryptArgs),
    /// Verify the proof of a rekeying or transcryption against the transcryptor's commitment and
    /// output the rekeyed ciphertext.
    VerifyRekey(VerifyRekeyArgs),
}

#[derive(Args)]
pub struct EncodeArgs {
    /// The identifier or value, as text.
    text: String,
}

#[derive(Args)]
pub struct DecodeArgs {
    /// The value (hex), or the blocks of a long value.
    #[arg(required = true)]
    value: Vec<String>,
}

#[derive(Args)]
pub struct EncryptArgs {
    /// The public key to encrypt for (hex).
    #[arg(long)]
    key: String,
    /// The key is a global public key instead of a session public key.
    #[arg(long)]
    global: bool,
    /// The value (hex), or the blocks of a long value.
    #[arg(required = true)]
    value: Vec<String>,
}

#[derive(Args)]
pub struct DecryptArgs {
    /// The secret key to decrypt with (hex).
    #[arg(long)]
    key: String,
    /// The key is a global secret key instead of a session secret key.
    #[cfg(feature = "insecure")]
    #[arg(long)]
    global: bool,
    /// The ciphertext (base64), or the `|`-separated blocks of a long one.
    #[arg(allow_hyphen_values = true)]
    ciphertext: String,
}

#[derive(Args)]
pub struct RerandomizeArgs {
    /// The public key the ciphertext is encrypted under (hex).
    #[cfg(not(feature = "elgamal3"))]
    #[arg(long)]
    key: String,
    /// The ciphertext (base64), or the `|`-separated blocks of a long one.
    #[arg(allow_hyphen_values = true)]
    ciphertext: String,
}

#[derive(Args)]
pub struct RekeyArgs {
    /// The public key the ciphertext is encrypted under (hex).
    #[cfg(not(feature = "elgamal3"))]
    #[arg(long)]
    key: String,
    /// The rekey factor from the current to the new session (hex).
    #[arg(long)]
    k: String,
    /// Also output a proof of the operation, to be verified against the transcryptor's
    /// commitments.
    #[arg(long)]
    prove: bool,
    /// The ciphertext (base64), or the `|`-separated blocks of a long one.
    #[arg(allow_hyphen_values = true)]
    ciphertext: String,
}

#[derive(Args)]
pub struct PseudonymizeArgs {
    /// The public key the ciphertext is encrypted under (hex).
    #[cfg(not(feature = "elgamal3"))]
    #[arg(long)]
    key: String,
    /// The reshuffle factor from the current to the new domain (hex).
    #[arg(long)]
    s: String,
    /// The rekey factor from the current to the new session (hex).
    #[arg(long)]
    k: String,
    /// Also output a proof of the operation, to be verified against the transcryptor's
    /// commitments.
    #[arg(long)]
    prove: bool,
    /// The ciphertext (base64), or the `|`-separated blocks of a long one.
    #[arg(allow_hyphen_values = true)]
    ciphertext: String,
}

#[derive(Args)]
pub struct TranscryptArgs {
    /// The public key the ciphertext is encrypted under (hex).
    #[cfg(not(feature = "elgamal3"))]
    #[arg(long)]
    key: String,
    #[command(flatten)]
    transition: TransitionArgs,
    /// Also output a proof of the operation, to be verified against the transcryptor's
    /// commitments.
    #[arg(long)]
    prove: bool,
    /// The ciphertext (base64), or the `|`-separated blocks of a long one.
    #[arg(allow_hyphen_values = true)]
    ciphertext: String,
}

#[derive(Args)]
pub struct AttributeTranscryptArgs {
    /// The public key the ciphertext is encrypted under (hex).
    #[cfg(not(feature = "elgamal3"))]
    #[arg(long)]
    key: String,
    #[command(flatten)]
    transition: AttributeTransitionArgs,
    /// Also output a proof of the operation, to be verified against the transcryptor's
    /// commitments.
    #[arg(long)]
    prove: bool,
    /// The ciphertext (base64), or the `|`-separated blocks of a long one.
    #[arg(allow_hyphen_values = true)]
    ciphertext: String,
}

/// The types that make up one kind of data, so that the commands are written once. The
/// encrypted types prove their rekeying with a proof that is printed and parsed as JSON.
pub trait Kind {
    type Plain: ElGamalEncryptable
        + Padded
        + Encryptable<
            Group = Ristretto255,
            EncryptedType = Self::Enc,
            PublicKeyType = Self::SessionPk,
            GlobalPublicKeyType = Self::GlobalPk,
        >;
    type Enc: ElGamalEncrypted
        + Encrypted<
            Group = Ristretto255,
            UnencryptedType = Self::Plain,
            SecretKeyType = Self::SessionSk,
        > + Rekeyable<RekeyInfo = Self::RekeyInfo>
        + Transcryptable
        + VerifiableRekeyable<
            RekeyProof: VerifiableRekeyProof<Output = Self::Enc> + Serialize + DeserializeOwned,
        >;
    type Long: Encryptable<
        EncryptedType = Self::LongEnc,
        PublicKeyType = Self::SessionPk,
        GlobalPublicKeyType = Self::GlobalPk,
    >;
    type LongEnc: Encrypted<
            Group = Ristretto255,
            UnencryptedType = Self::Long,
            SecretKeyType = Self::SessionSk,
        > + Rekeyable<RekeyInfo = Self::RekeyInfo>
        + Transcryptable
        + VerifiableRekeyable<
            RekeyProof: VerifiableRekeyProof<Output = Self::LongEnc> + Serialize + DeserializeOwned,
        >;
    type SessionPk: PublicKey<Group = Ristretto255>;
    type SessionSk: SecretKey<Group = Ristretto255>;
    type GlobalPk: PublicKey<Group = Ristretto255>;
    #[cfg(feature = "insecure")]
    type GlobalSk: SecretKey<Group = Ristretto255>;
    /// The info of a rekeying, which also gives the commitment to its factor.
    type RekeyInfo: Copy + Into<VerifiableRekeyCommitment>;

    fn rekey_info(k: ScalarNonZero) -> Self::RekeyInfo;
    /// The public key a ciphertext is encrypted under after rekeying with `info`.
    #[cfg_attr(feature = "elgamal3", allow(dead_code))]
    fn rekey_public_key(info: &Self::RekeyInfo, before: &Self::SessionPk) -> Self::SessionPk;
    fn long_from_blocks(blocks: Vec<Self::Plain>) -> Self::Long;
    fn long_from_text(text: &str) -> Self::Long;
    fn long_to_text(long: &Self::Long) -> std::result::Result<String, PaddingError>;
    fn long_to_hex(long: &Self::Long) -> String;
    fn long_enc_serialize(long: &Self::LongEnc) -> String;
    fn long_enc_deserialize(text: &str) -> std::result::Result<Self::LongEnc, ParseError>;
    #[cfg(feature = "insecure")]
    fn decrypt_global(enc: &Self::Enc, key: &Self::GlobalSk) -> Result<Self::Plain>;
    #[cfg(feature = "insecure")]
    fn decrypt_global_long(enc: &Self::LongEnc, key: &Self::GlobalSk) -> Result<Self::Long>;
}

pub struct PseudonymKind;
pub struct AttributeKind;

macro_rules! impl_kind {
    ($kind:ty {
        plain: $plain:ty, enc: $enc:ty, long: $long:ident, long_enc: $long_enc:ident,
        session_pk: $spk:ty, session_sk: $ssk:ty, global_pk: $gpk:ty, global_sk: $gsk:ty,
        rekey_info: $info:ty, rekey_factor: $factor:ty
    }) => {
        impl Kind for $kind {
            type Plain = $plain;
            type Enc = $enc;
            type Long = $long;
            type LongEnc = $long_enc;
            type SessionPk = $spk;
            type SessionSk = $ssk;
            type GlobalPk = $gpk;
            #[cfg(feature = "insecure")]
            type GlobalSk = $gsk;
            type RekeyInfo = $info;

            fn rekey_info(k: ScalarNonZero) -> Self::RekeyInfo {
                <$info>::from(<$factor>::from(k))
            }
            fn rekey_public_key(
                info: &Self::RekeyInfo,
                before: &Self::SessionPk,
            ) -> Self::SessionPk {
                info.rekey_public_key(before)
            }
            fn long_from_blocks(blocks: Vec<Self::Plain>) -> Self::Long {
                $long(blocks)
            }
            fn long_from_text(text: &str) -> Self::Long {
                $long::from_string_padded(text)
            }
            fn long_to_text(long: &Self::Long) -> std::result::Result<String, PaddingError> {
                long.to_string_padded()
            }
            fn long_to_hex(long: &Self::Long) -> String {
                long.0
                    .iter()
                    .map(|b| b.to_hex())
                    .collect::<Vec<_>>()
                    .join(" ")
            }
            fn long_enc_serialize(long: &Self::LongEnc) -> String {
                long.serialize()
            }
            fn long_enc_deserialize(text: &str) -> std::result::Result<Self::LongEnc, ParseError> {
                $long_enc::deserialize(text)
            }
            #[cfg(feature = "insecure")]
            fn decrypt_global(enc: &Self::Enc, key: &Self::GlobalSk) -> Result<Self::Plain> {
                #[cfg(feature = "elgamal3")]
                return enc.decrypt_global(key).ok_or_else(io::Error::key_mismatch);
                #[cfg(not(feature = "elgamal3"))]
                Ok(enc.decrypt_global(key))
            }
            #[cfg(feature = "insecure")]
            fn decrypt_global_long(
                enc: &Self::LongEnc,
                key: &Self::GlobalSk,
            ) -> Result<Self::Long> {
                #[cfg(feature = "elgamal3")]
                return enc.decrypt_global(key).ok_or_else(io::Error::key_mismatch);
                #[cfg(not(feature = "elgamal3"))]
                Ok(enc.decrypt_global(key))
            }
        }
    };
}

impl_kind!(PseudonymKind {
    plain: Pseudonym,
    enc: EncryptedPseudonym,
    long: LongPseudonym,
    long_enc: LongEncryptedPseudonym,
    session_pk: PseudonymSessionPublicKey,
    session_sk: PseudonymSessionSecretKey,
    global_pk: PseudonymGlobalPublicKey,
    global_sk: PseudonymGlobalSecretKey,
    rekey_info: PseudonymRekeyInfo,
    rekey_factor: PseudonymRekeyFactor
});

impl_kind!(AttributeKind {
    plain: Attribute,
    enc: EncryptedAttribute,
    long: LongAttribute,
    long_enc: LongEncryptedAttribute,
    session_pk: AttributeSessionPublicKey,
    session_sk: AttributeSessionSecretKey,
    global_pk: AttributeGlobalPublicKey,
    global_sk: AttributeGlobalSecretKey,
    rekey_info: AttributeRekeyInfo,
    rekey_factor: AttributeRekeyFactor
});

/// A plain value of one kind, short or long.
enum Value<K: Kind> {
    Short(K::Plain),
    Long(K::Long),
}

impl<K: Kind> Value<K> {
    fn parse(raw: &[String]) -> Result<Self> {
        // Long values are given as separate blocks or as one run of concatenated blocks.
        let blocks = io::read_values(raw)?
            .iter()
            .flat_map(|token| {
                if token.len() > HEX_BLOCK && token.len() % HEX_BLOCK == 0 {
                    token
                        .as_bytes()
                        .chunks(HEX_BLOCK)
                        .map(|c| String::from_utf8_lossy(c).into_owned())
                        .collect::<Vec<_>>()
                } else {
                    vec![token.clone()]
                }
            })
            .collect::<Vec<_>>()
            .iter()
            .map(|hex| {
                K::Plain::from_hex(hex).ok_or_else(|| {
                    io::Error::input(format!(
                        "value: {hex} is not a valid group element (64 hex digits)"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(if blocks.len() == 1 {
            Value::Short(blocks.into_iter().next().expect("one block"))
        } else {
            Value::<K>::Long(K::long_from_blocks(blocks))
        })
    }

    fn emit(&self, out: &mut Output) {
        match self {
            Value::<K>::Short(v) => out.value("value", v.to_hex()),
            Value::<K>::Long(v) => out.value("value", K::long_to_hex(v)),
        }
    }
}

/// An encrypted value of one kind, short or long.
pub enum Cipher<K: Kind> {
    Short(K::Enc),
    Long(K::LongEnc),
}

impl<K: Kind> Cipher<K> {
    pub fn parse(raw: &str) -> Result<Self> {
        let text = io::read_arg(raw)?;
        if text.contains('|') {
            K::long_enc_deserialize(&text)
                .map(Cipher::Long)
                .map_err(|_| io::Error::input("ciphertext: expected `|`-separated base64 blocks"))
        } else {
            K::Enc::from_base64(&text)
                .map(Cipher::Short)
                .ok_or_else(|| io::Error::input("ciphertext: expected a base64-encoded ciphertext"))
        }
    }

    pub fn emit(&self, out: &mut Output) {
        match self {
            Cipher::Short(c) => out.value("ciphertext", c.to_base64()),
            Cipher::Long(c) => out.value("ciphertext", K::long_enc_serialize(c)),
        }
    }
}

/// Encode text the way the library, the JSON documents and the bindings do: PKCS#7-padded into
/// one block when it fits (up to 15 bytes), else into a long value.
fn encode<K: Kind>(args: EncodeArgs, out: &mut Output) -> Result<()> {
    let text = io::read_arg(&args.text)?;
    match K::Plain::from_string_padded(&text) {
        Ok(value) => out.value("value", value.to_hex()),
        Err(_) => {
            let long = K::long_from_text(&text);
            out.note(
                "The value is longer than 15 bytes and is encoded as a long value with PKCS#7 padding. \
                 The number of blocks is visible, and blocks can reveal subgroups.",
            );
            out.value("value", K::long_to_hex(&long));
        }
    }
    Ok(())
}

fn decode<K: Kind>(args: DecodeArgs, out: &mut Output) -> Result<()> {
    let text = match Value::<K>::parse(&args.value)? {
        Value::<K>::Short(v) => v.to_string_padded(),
        Value::<K>::Long(v) => K::long_to_text(&v),
    }
    .map_err(|e| io::Error::input(format!("the value does not encode text: {e}")))?;
    out.value("text", text);
    Ok(())
}

fn encrypt<K: Kind, R: Rng + CryptoRng>(
    args: EncryptArgs,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    let value = Value::<K>::parse(&args.value)?;
    let cipher = if args.global {
        let key: K::GlobalPk = io::public_key(&args.key, "global public key")?;
        match value {
            Value::<K>::Short(v) => Cipher::<K>::Short(v.encrypt_global(&key, rng)),
            Value::<K>::Long(v) => Cipher::<K>::Long(v.encrypt_global(&key, rng)),
        }
    } else {
        let key: K::SessionPk = io::public_key(&args.key, "session public key")?;
        match value {
            Value::<K>::Short(v) => Cipher::<K>::Short(v.encrypt(&key, rng)),
            Value::<K>::Long(v) => Cipher::<K>::Long(v.encrypt(&key, rng)),
        }
    };
    cipher.emit(out);
    Ok(())
}

fn decrypt<K: Kind>(args: DecryptArgs, out: &mut Output) -> Result<()> {
    #[cfg(feature = "insecure")]
    if args.global {
        let key: K::GlobalSk = io::secret_key(&args.key, "global secret key")?;
        let cipher = Cipher::<K>::parse(&args.ciphertext)?;
        let value = match cipher {
            Cipher::Short(c) => Value::<K>::Short(K::decrypt_global(&c, &key)?),
            Cipher::Long(c) => Value::<K>::Long(K::decrypt_global_long(&c, &key)?),
        };
        value.emit(out);
        return Ok(());
    }
    let key: K::SessionSk = io::secret_key(&args.key, "session secret key")?;
    let cipher = Cipher::<K>::parse(&args.ciphertext)?;
    #[cfg(feature = "elgamal3")]
    let value = match cipher {
        Cipher::Short(c) => Value::<K>::Short(c.decrypt(&key).ok_or_else(io::Error::key_mismatch)?),
        Cipher::Long(c) => Value::<K>::Long(c.decrypt(&key).ok_or_else(io::Error::key_mismatch)?),
    };
    #[cfg(not(feature = "elgamal3"))]
    let value = match cipher {
        Cipher::Short(c) => Value::<K>::Short(c.decrypt(&key)),
        Cipher::Long(c) => Value::<K>::Long(c.decrypt(&key)),
    };
    value.emit(out);
    Ok(())
}

fn rerandomize<K: Kind, R: Rng + CryptoRng>(
    args: RerandomizeArgs,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    let cipher = Cipher::<K>::parse(&args.ciphertext)?;
    #[cfg(feature = "elgamal3")]
    let result = match cipher {
        Cipher::Short(c) => Cipher::<K>::Short(c.rerandomize(rng)),
        Cipher::Long(c) => Cipher::<K>::Long(c.rerandomize(rng)),
    };
    #[cfg(not(feature = "elgamal3"))]
    let result = {
        let key: K::SessionPk = io::public_key(&args.key, "public key")?;
        match cipher {
            Cipher::Short(c) => Cipher::<K>::Short(c.rerandomize(&key, rng)),
            Cipher::Long(c) => Cipher::<K>::Long(c.rerandomize(&key, rng)),
        }
    };
    result.emit(out);
    Ok(())
}

/// Apply a transcryption operation to a short or long ciphertext; without `elgamal3` the
/// operation also takes the public key the ciphertext is encrypted under.
macro_rules! transcrypted {
    ($kind:ty, $cipher:expr, $rng:expr, $key:ident, $info:expr, $op:ident) => {{
        #[cfg(feature = "elgamal3")]
        let result = match $cipher {
            Cipher::Short(c) => Cipher::<$kind>::Short(c.$op($info, $rng)),
            Cipher::Long(c) => Cipher::<$kind>::Long(c.$op($info, $rng)),
        };
        #[cfg(not(feature = "elgamal3"))]
        let result = match $cipher {
            Cipher::Short(c) => Cipher::<$kind>::Short(c.$op($info, &$key, $rng)),
            Cipher::Long(c) => Cipher::<$kind>::Long(c.$op($info, &$key, $rng)),
        };
        result
    }};
}

/// Without `elgamal3`, emit the public key a transcrypted ciphertext is now encrypted under,
/// which the next transcryptor (or the storage) needs to rerandomize it.
macro_rules! emit_next_key {
    ($out:expr, $key:ident, $next_key:expr) => {
        #[cfg(not(feature = "elgamal3"))]
        $out.value("key", $next_key(&$key).to_hex());
    };
}

fn rekey<K: Kind, R: Rng + CryptoRng>(
    args: RekeyArgs,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    let info = K::rekey_info(io::scalar(&args.k, "k")?);
    let cipher = Cipher::<K>::parse(&args.ciphertext)?;
    #[cfg(not(feature = "elgamal3"))]
    let key: K::SessionPk = io::public_key(&args.key, "public key")?;
    if args.prove {
        verifiable::prove_rekey(&cipher, &info, rng, out);
    } else {
        transcrypted!(K, cipher, rng, key, &info, rekey).emit(out);
    }
    emit_next_key!(out, key, |key| K::rekey_public_key(&info, key));
    Ok(())
}

/// Pseudonymize an encrypted pseudonym with `info`, with a proof if `prove`.
fn pseudonymize_with<R: Rng + CryptoRng>(
    info: &PseudonymizationInfo,
    #[cfg(not(feature = "elgamal3"))] key_arg: &str,
    prove: bool,
    ciphertext: &str,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    let cipher = Cipher::<PseudonymKind>::parse(ciphertext)?;
    #[cfg(not(feature = "elgamal3"))]
    let key: PseudonymSessionPublicKey = io::public_key(key_arg, "public key")?;
    if prove {
        #[cfg(feature = "elgamal3")]
        verifiable::prove_pseudonymize(&cipher, info, rng, out);
        #[cfg(not(feature = "elgamal3"))]
        verifiable::prove_pseudonymize(&cipher, info, &key, rng, out);
    } else {
        transcrypted!(PseudonymKind, cipher, rng, key, info, pseudonymize).emit(out);
    }
    emit_next_key!(out, key, |key| info.rekey_public_key(key));
    Ok(())
}

fn pseudonymize<R: Rng + CryptoRng>(
    args: PseudonymizeArgs,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    let info = PseudonymizationInfo {
        s: ReshuffleFactor::from(io::scalar(&args.s, "s")?),
        k: PseudonymRekeyFactor::from(io::scalar(&args.k, "k")?),
    };
    pseudonymize_with(
        &info,
        #[cfg(not(feature = "elgamal3"))]
        &args.key,
        args.prove,
        &args.ciphertext,
        rng,
        out,
    )
}

fn transcrypt_pseudonym<R: Rng + CryptoRng>(
    args: TranscryptArgs,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    let info = args.transition.info()?;
    pseudonymize_with(
        &info.pseudonym,
        #[cfg(not(feature = "elgamal3"))]
        &args.key,
        args.prove,
        &args.ciphertext,
        rng,
        out,
    )
}

fn transcrypt_attribute<R: Rng + CryptoRng>(
    args: AttributeTranscryptArgs,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    let info = args.transition.info()?;
    let cipher = Cipher::<AttributeKind>::parse(&args.ciphertext)?;
    #[cfg(not(feature = "elgamal3"))]
    let key: AttributeSessionPublicKey = io::public_key(&args.key, "public key")?;
    if args.prove {
        verifiable::prove_rekey(&cipher, &info, rng, out);
    } else {
        transcrypted!(AttributeKind, cipher, rng, key, &info, rekey).emit(out);
    }
    emit_next_key!(out, key, |key| info.rekey_public_key(key));
    Ok(())
}

pub fn run_pseudonym<R: Rng + CryptoRng>(
    cmd: PseudonymCommand,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    match cmd {
        PseudonymCommand::Random => {
            out.value("value", Pseudonym::random(rng).to_hex());
            Ok(())
        }
        PseudonymCommand::Encode(args) => encode::<PseudonymKind>(args, out),
        PseudonymCommand::Decode(args) => decode::<PseudonymKind>(args, out),
        PseudonymCommand::Encrypt(args) => encrypt::<PseudonymKind, R>(args, rng, out),
        PseudonymCommand::Decrypt(args) => decrypt::<PseudonymKind>(args, out),
        PseudonymCommand::Rerandomize(args) => rerandomize::<PseudonymKind, R>(args, rng, out),
        PseudonymCommand::Rekey(args) => rekey::<PseudonymKind, R>(args, rng, out),
        PseudonymCommand::Pseudonymize(args) => pseudonymize(args, rng, out),
        PseudonymCommand::Transcrypt(args) => transcrypt_pseudonym(args, rng, out),
        PseudonymCommand::VerifyRekey(args) => verifiable::verify_rekey::<PseudonymKind>(args, out),
        PseudonymCommand::VerifyPseudonymize(args) => verifiable::verify_pseudonymize(args, out),
    }
}

pub fn run_attribute<R: Rng + CryptoRng>(
    cmd: AttributeCommand,
    rng: &mut R,
    out: &mut Output,
) -> Result<()> {
    match cmd {
        AttributeCommand::Random => {
            out.value("value", Attribute::random(rng).to_hex());
            Ok(())
        }
        AttributeCommand::Encode(args) => encode::<AttributeKind>(args, out),
        AttributeCommand::Decode(args) => decode::<AttributeKind>(args, out),
        AttributeCommand::Encrypt(args) => encrypt::<AttributeKind, R>(args, rng, out),
        AttributeCommand::Decrypt(args) => decrypt::<AttributeKind>(args, out),
        AttributeCommand::Rerandomize(args) => rerandomize::<AttributeKind, R>(args, rng, out),
        AttributeCommand::Rekey(args) => rekey::<AttributeKind, R>(args, rng, out),
        AttributeCommand::Transcrypt(args) => transcrypt_attribute(args, rng, out),
        AttributeCommand::VerifyRekey(args) => verifiable::verify_rekey::<AttributeKind>(args, out),
    }
}
