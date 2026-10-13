//! Test vectors for the ristretto255-SHA512 ciphersuite.
//!
//! The expected values live as Rust constants in `tests/vectors/expected.rs`, one per line, and
//! this file recomputes every one of them and asserts equality. Any change in derived factors,
//! encodings, transcryption or proofs therefore fails the test instead of passing silently.
//!
//! Every random input is fixed: the transcryptor secrets and identifiers are literals, and every
//! scalar the protocol samples (the blinding `b` of each encryption, the rerandomization `r` of
//! each transcryption, the batch permutation, and each proof's nonce) comes from a ChaCha20 RNG
//! with the explicit [`SEED`] below.
//!
//! To update the constants after an intended change, run
//!
//! ```text
//! cargo test --features batch,verifiable --test vectors -- --ignored --nocapture
//! ```
//!
//! which prints the current values in the layout of `expected.rs`; copy the output there after
//! checking the diff value by value.
//!
//! The vectors cover the batch operations and the verifiable session key share, so the test is
//! compiled out without those features. It is also compiled out under `elgamal3`, whose
//! ciphertext carries a third element: a ciphertext here is `B || C`, 2 * Ne bytes, so the
//! `elgamal3` encoding is a different wire format and is not covered. Every scalar
//! and Element below is identical under both encodings; only the ciphertexts differ.
//!
//! The vectors also assume the default `DeriveFactor`, so the test is compiled out under the
//! `legacy` feature, which selects the PEP repository's derivation instead.

#![cfg(all(
    feature = "batch",
    feature = "verifiable",
    not(feature = "legacy"),
    not(feature = "elgamal3")
))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::data::simple::{ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym};
use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
use libpep::elgamal::arithmetic::hashing::hash_to_group;
use libpep::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use libpep::elgamal::arithmetic::{Group, Ristretto255};
use libpep::elgamal::ElGamal;
use libpep::factors::derivation::{LABEL_REKEY_ATTRIBUTE, LABEL_REKEY_PSEUDONYM, LABEL_RESHUFFLE};
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymisation_factor,
};
use libpep::factors::{
    AttributeRekeyInfo, EncryptionSecret, PseudonymizationInfo, PseudonymizationSecret, RekeyFactor,
};
use libpep::keys::distribution::proofs::{BlindingCommitment, SessionKeyShareProof};
use libpep::keys::traits::{PublicKey, SecretKey};
use libpep::keys::{
    make_attribute_session_keys, make_pseudonym_session_keys, AttributeGlobalSecretKey,
    PseudonymGlobalSecretKey,
};
use libpep::transcryptor::{pseudonymize_batch, rekey_batch};
use rand::rngs::ChaCha20Rng;
use rand::SeedableRng;
use std::fmt::Write as _;

#[path = "vectors/expected.rs"]
mod expected;

/// The seed of every ChaCha20 RNG used below, recorded as [`expected::SEED`].
const SEED: [u8; 32] = *b"libpep-ristretto255-SHA512-vec-1";

/// A ChaCha20 RNG seeded with [`SEED`] and a one-byte stream label, so that each vector group
/// draws from its own reproducible stream.
fn rng_for(label: u8) -> ChaCha20Rng {
    let mut seed = SEED;
    seed[31] = label;
    ChaCha20Rng::from_seed(seed)
}

fn ciphertext_hex(c: &ElGamal) -> String {
    hex::encode(c.to_bytes())
}

/// Every label and the constant it is expected to equal, in file order.
const EXPECTED: &[(&str, &str)] = &[
    ("Ciphersuite", expected::CIPHERSUITE),
    ("ContextString", expected::CONTEXTSTRING),
    ("Seed", expected::SEED),
    ("PS_1", expected::PS_1),
    ("ES_1", expected::ES_1),
    ("DomainIdentifier", expected::DOMAINIDENTIFIER),
    ("SessionIdentifier", expected::SESSIONIDENTIFIER),
    ("labelRekeyPseudonym", expected::SCALAR_LABELREKEYPSEUDONYM),
    ("k_c", expected::SCALAR_K_C),
    ("K_c", expected::K_C),
    ("labelRekeyAttribute", expected::SCALAR_LABELREKEYATTRIBUTE),
    ("k'_c", expected::SCALAR_K_PRIME_C),
    ("K'_c", expected::K_PRIME_C),
    ("labelReshuffle", expected::SCALAR_LABELRESHUFFLE),
    ("s_d", expected::SCALAR_S_D),
    ("S_d", expected::S_D),
    ("Identifier", expected::IDENTIFIER),
    ("M", expected::M),
    ("y", expected::SCALAR_Y),
    ("Y", expected::Y),
    ("DomainFrom", expected::DOMAINFROM),
    ("DomainTo", expected::DOMAINTO),
    ("SessionFrom", expected::SESSIONFROM),
    ("SessionTo", expected::SESSIONTO),
    ("pk_from", expected::SCALAR_PK_FROM),
    ("b", expected::SCALAR_B),
    ("V", expected::V),
    ("s", expected::SCALAR_S),
    ("k", expected::SCALAR_K),
    ("r", expected::SCALAR_R),
    ("V'", expected::V_PRIME),
    ("Y_to", expected::Y_TO),
    ("P", expected::P),
    ("sk_to", expected::SCALAR_SK_TO),
    ("BatchSeed", expected::BATCHSEED),
    ("typePseudonym", expected::SCALAR_TYPEPSEUDONYM),
    ("typeAttribute", expected::SCALAR_TYPEATTRIBUTE),
    ("PseudonymInput_0", expected::PSEUDONYMINPUT_0),
    ("PseudonymM_0", expected::PSEUDONYMM_0),
    ("PseudonymB_0", expected::PSEUDONYMB_0),
    ("PseudonymV_0", expected::PSEUDONYMV_0),
    ("PseudonymInput_1", expected::PSEUDONYMINPUT_1),
    ("PseudonymM_1", expected::PSEUDONYMM_1),
    ("PseudonymB_1", expected::PSEUDONYMB_1),
    ("PseudonymV_1", expected::PSEUDONYMV_1),
    ("PseudonymInput_2", expected::PSEUDONYMINPUT_2),
    ("PseudonymM_2", expected::PSEUDONYMM_2),
    ("PseudonymB_2", expected::PSEUDONYMB_2),
    ("PseudonymV_2", expected::PSEUDONYMV_2),
    ("PseudonymOut_0", expected::PSEUDONYMOUT_0),
    ("PseudonymOut_1", expected::PSEUDONYMOUT_1),
    ("PseudonymOut_2", expected::PSEUDONYMOUT_2),
    ("PseudonymP_0", expected::PSEUDONYMP_0),
    ("PseudonymP_1", expected::PSEUDONYMP_1),
    ("PseudonymP_2", expected::PSEUDONYMP_2),
    ("PseudonymPermutation", expected::PSEUDONYMPERMUTATION),
    ("AttributeM_0", expected::ATTRIBUTEM_0),
    ("AttributeB_0", expected::ATTRIBUTEB_0),
    ("AttributeV_0", expected::ATTRIBUTEV_0),
    ("AttributeM_1", expected::ATTRIBUTEM_1),
    ("AttributeB_1", expected::ATTRIBUTEB_1),
    ("AttributeV_1", expected::ATTRIBUTEV_1),
    ("AttributeM_2", expected::ATTRIBUTEM_2),
    ("AttributeB_2", expected::ATTRIBUTEB_2),
    ("AttributeV_2", expected::ATTRIBUTEV_2),
    ("k_attribute", expected::SCALAR_K_ATTRIBUTE),
    ("AttributeOut_0", expected::ATTRIBUTEOUT_0),
    ("AttributeOut_1", expected::ATTRIBUTEOUT_1),
    ("AttributeOut_2", expected::ATTRIBUTEOUT_2),
    ("AttributeP_0", expected::ATTRIBUTEP_0),
    ("AttributeP_1", expected::ATTRIBUTEP_1),
    ("AttributeP_2", expected::ATTRIBUTEP_2),
    ("AttributePermutation", expected::ATTRIBUTEPERMUTATION),
    ("b_1", expected::SCALAR_B_1),
    ("B_1", expected::B_1),
    ("K_c_1", expected::K_C_1),
    ("u_1", expected::SCALAR_U_1),
    ("U_1", expected::U_1),
];

/// The expected value for `name`.
fn expected_for(name: &str) -> &'static str {
    EXPECTED
        .iter()
        .find(|(label, _)| *label == name)
        .map(|(_, value)| *value)
        .unwrap_or_else(|| {
            panic!("no expected constant for {name}; add it to tests/vectors/expected.rs")
        })
}

/// Record a computed value and check it against its constant.
///
/// `out` collects the values in the layout of `expected.rs`, so that the ignored
/// `print_vectors_for_copying` test can emit them; the assertion is what makes this a test.
fn put(out: &mut String, name: &str, value: &str) {
    writeln!(
        out,
        "/// `{name}`\npub const {}: &str = \"{value}\";",
        const_name(name)
    )
    .expect("writing to a String cannot fail");
    if CHECK.with(|c| c.get()) {
        assert_eq!(
            value,
            expected_for(name),
            "{name} differs from tests/vectors/expected.rs. If this change is intended, \
             regenerate the constants with: cargo test --features batch,verifiable --test \
             vectors -- --ignored --nocapture"
        );
    }
}

thread_local! {
    /// Whether [`put`] asserts. The printer turns it off so it can emit changed values.
    static CHECK: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// The constant name for a protocol label: scalar names are lower-case and would collide with
/// the group element of the same name once upper-cased, so they carry a `SCALAR_` prefix.
fn const_name(label: &str) -> String {
    let base: String = label
        .replace('\'', "_PRIME")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    match label.chars().find(|c| c.is_ascii_alphabetic()) {
        Some(c) if c.is_ascii_lowercase() => format!("SCALAR_{}", base.to_uppercase()),
        _ => base.to_uppercase(),
    }
}

/// The three `DeriveFactor` labels, each with its own secret and identifier.
fn vectors_derive_factor(out: &mut String) {
    let pseudo_secret =
        PseudonymizationSecret::from(b"transcryptor-1-pseudonymization-secret".to_vec());
    let enc_secret = EncryptionSecret::from(b"transcryptor-1-encryption-secret".to_vec());
    let domain = PseudonymizationDomain::from("domain-a");
    let session = EncryptionContext::from("session-a");

    out.push_str("// DeriveFactor, the three labels of Table 1.\n");
    out.push_str("// The secrets are ASCII byte strings, shown here as hex.\n\n");

    put(
        out,
        "PS_1",
        &hex::encode(b"transcryptor-1-pseudonymization-secret"),
    );
    put(
        out,
        "ES_1",
        &hex::encode(b"transcryptor-1-encryption-secret"),
    );
    put(out, "DomainIdentifier", &hex::encode(b"domain-a"));
    put(out, "SessionIdentifier", &hex::encode(b"session-a"));
    out.push('\n');

    let k = make_pseudonym_rekey_factor(&enc_secret, &session);
    put(
        out,
        "labelRekeyPseudonym",
        &format!("{LABEL_REKEY_PSEUDONYM:02x}"),
    );
    put(out, "k_c", &k.scalar().to_hex());
    put(out, "K_c", &(k.scalar() * G).to_hex());
    out.push('\n');

    let ka = make_attribute_rekey_factor(&enc_secret, &session);
    put(
        out,
        "labelRekeyAttribute",
        &format!("{LABEL_REKEY_ATTRIBUTE:02x}"),
    );
    put(out, "k'_c", &ka.scalar().to_hex());
    put(out, "K'_c", &(ka.scalar() * G).to_hex());
    out.push('\n');

    let s = make_pseudonymisation_factor(&pseudo_secret, &domain);
    put(out, "labelReshuffle", &format!("{LABEL_RESHUFFLE:02x}"));
    put(out, "s_d", &s.scalar().to_hex());
    put(out, "S_d", &(s.scalar() * G).to_hex());
}

/// EncryptPseudonym, TranscryptPseudonym and Decrypt with fixed `b` and `r`.
fn vectors_single_pseudonym(out: &mut String) {
    let mut rng = rng_for(0x01);

    let pseudo_secret =
        PseudonymizationSecret::from(b"transcryptor-1-pseudonymization-secret".to_vec());
    let enc_secret = EncryptionSecret::from(b"transcryptor-1-encryption-secret".to_vec());

    let domain_from = PseudonymizationDomain::from("domain-a");
    let domain_to = PseudonymizationDomain::from("domain-b");
    let session_from = EncryptionContext::from("session-a");
    let session_to = EncryptionContext::from("session-b");

    // The global key pair of the setup authority, fixed here rather than sampled.
    let y = ScalarNonZero::random(&mut rng);
    let global_secret = PseudonymGlobalSecretKey::from_scalar(y);

    let (pk_from, _sk_from) =
        make_pseudonym_session_keys(&global_secret, &session_from, &enc_secret);
    let (_pk_to, sk_to) = make_pseudonym_session_keys(&global_secret, &session_to, &enc_secret);

    // The identifier is encoded with hash_to_group.
    let identifier = b"patient-42";
    let m = hash_to_group::<Ristretto255>(identifier);

    // Enc(M, pk_from) with an explicit blinding scalar b.
    let b = ScalarNonZero::random(&mut rng);
    let ciphertext = ElGamal {
        gb: b * G,
        gc: m + b * *pk_from.value(),
    };
    let encrypted = EncryptedPseudonym::from_value(ciphertext);

    out.push_str("// EncryptPseudonym / TranscryptPseudonym / Decrypt, one ciphertext.\n");
    out.push_str("// y is the global secret key; b is the encryption blinding scalar;\n");
    out.push_str("// r is the rerandomization scalar of the transcryption.\n\n");

    put(out, "Identifier", &hex::encode(identifier));
    put(out, "M", &m.to_hex());
    put(out, "y", &y.to_hex());
    put(out, "Y", &(y * G).to_hex());
    put(out, "DomainFrom", &hex::encode(b"domain-a"));
    put(out, "DomainTo", &hex::encode(b"domain-b"));
    put(out, "SessionFrom", &hex::encode(b"session-a"));
    put(out, "SessionTo", &hex::encode(b"session-b"));
    put(out, "pk_from", &pk_from.value().to_hex());
    put(out, "b", &b.to_hex());
    put(out, "V", &ciphertext_hex(encrypted.value()));
    out.push('\n');

    // The transcryption factors, and the ratio actually applied.
    let info = PseudonymizationInfo::new(
        &domain_from,
        &domain_to,
        &session_from,
        &session_to,
        &pseudo_secret,
        &enc_secret,
    );
    put(out, "s", &info.s.scalar().to_hex());
    put(out, "k", &info.k.scalar().to_hex());

    // RRSK with an explicit r.
    let r = ScalarNonZero::random(&mut rng);
    let s = info.s.scalar();
    let k = info.k.scalar();
    let rerandomized = ElGamal {
        gb: ciphertext.gb + r * G,
        gc: ciphertext.gc + r * *pk_from.value(),
    };
    let transcrypted = ElGamal {
        gb: s * k.invert() * rerandomized.gb,
        gc: s * rerandomized.gc,
    };
    put(out, "r", &r.to_hex());
    put(out, "V'", &ciphertext_hex(&transcrypted));
    put(out, "Y_to", &(k * *pk_from.value()).to_hex());
    out.push('\n');

    // Decrypt, and the same pseudonym reached by the library's own transcryption path.
    let decrypted = transcrypted.gc - sk_to.value() * transcrypted.gb;
    put(out, "P", &decrypted.to_hex());
    put(out, "sk_to", &sk_to.value().to_hex());

    // The pseudonym is s * M, independent of the rerandomization.
    assert_eq!(decrypted, s * m, "decryption must yield s * M");
}

/// A three-element batch in both modes, with the permutation drawn from the recorded seed.
fn vectors_batch(out: &mut String) {
    let mut rng = rng_for(0x02);

    let pseudo_secret =
        PseudonymizationSecret::from(b"transcryptor-1-pseudonymization-secret".to_vec());
    let enc_secret = EncryptionSecret::from(b"transcryptor-1-encryption-secret".to_vec());

    let domain_from = PseudonymizationDomain::from("domain-a");
    let domain_to = PseudonymizationDomain::from("domain-b");
    let session_from = EncryptionContext::from("session-a");
    let session_to = EncryptionContext::from("session-b");

    let y = ScalarNonZero::random(&mut rng);
    let pseudonym_global = PseudonymGlobalSecretKey::from_scalar(y);
    let y_attr = ScalarNonZero::random(&mut rng);
    let attribute_global = AttributeGlobalSecretKey::from_scalar(y_attr);

    let (pk_from, _) = make_pseudonym_session_keys(&pseudonym_global, &session_from, &enc_secret);
    let (_, sk_to) = make_pseudonym_session_keys(&pseudonym_global, &session_to, &enc_secret);
    let (apk_from, _) = make_attribute_session_keys(&attribute_global, &session_from, &enc_secret);
    let (_, ask_to) = make_attribute_session_keys(&attribute_global, &session_to, &enc_secret);

    out.push_str("// A batch of three pseudonyms (typePseudonym, 0x01) and three attributes\n");
    out.push_str("// (typeAttribute, 0x02). The permutation and every r are drawn from the\n");
    out.push_str("// recorded seed with stream label 02, so the output order is reproducible.\n\n");

    put(out, "BatchSeed", &hex::encode(rng_for(0x02).get_seed()));
    put(out, "typePseudonym", "01");
    put(out, "typeAttribute", "02");
    out.push('\n');

    // Three pseudonyms.
    let identifiers: [&[u8]; 3] = [b"patient-1", b"patient-2", b"patient-3"];
    let mut pseudonyms = Vec::new();
    for (i, id) in identifiers.iter().enumerate() {
        let m = hash_to_group::<Ristretto255>(id);
        let b = ScalarNonZero::random(&mut rng);
        let c = ElGamal {
            gb: b * G,
            gc: m + b * *pk_from.value(),
        };
        put(out, &format!("PseudonymInput_{i}"), &hex::encode(id));
        put(out, &format!("PseudonymM_{i}"), &m.to_hex());
        put(out, &format!("PseudonymB_{i}"), &b.to_hex());
        put(out, &format!("PseudonymV_{i}"), &ciphertext_hex(&c));
        pseudonyms.push(EncryptedPseudonym::from_value(c));
    }
    out.push('\n');

    let info = PseudonymizationInfo::new(
        &domain_from,
        &domain_to,
        &session_from,
        &session_to,
        &pseudo_secret,
        &enc_secret,
    );

    let transcrypted = pseudonymize_batch(&mut pseudonyms.clone(), &info, &pk_from, &mut rng)
        .expect("batch pseudonymization should succeed");

    for (i, c) in transcrypted.iter().enumerate() {
        put(
            out,
            &format!("PseudonymOut_{i}"),
            &ciphertext_hex(c.value()),
        );
    }
    // The decrypted pseudonyms, and the permutation the shuffle applied. The pseudonym in
    // position j of the output is s * M of input PseudonymPermutation[j]; a verifier recomputes
    // s * M for each input and matches. The permutation is recorded so the vector is checkable,
    // but a transcryptor MUST NOT disclose it in a real deployment.
    let s = info.s.scalar();
    let mut permutation = Vec::new();
    for (i, c) in transcrypted.iter().enumerate() {
        let p = c.value().gc - sk_to.value() * c.value().gb;
        put(out, &format!("PseudonymP_{i}"), &p.to_hex());
        let source = (0..3)
            .find(|&j| s * hash_to_group::<Ristretto255>(identifiers[j]) == p)
            .expect("every output pseudonym comes from one of the inputs");
        permutation.push(source.to_string());
    }
    put(out, "PseudonymPermutation", &permutation.join(","));
    out.push('\n');

    // Three attributes, rekeyed only. Attributes are arbitrary group elements, so they are drawn
    // from the recorded stream rather than encoded from an identifier.
    let mut attributes = Vec::new();
    let mut attribute_messages = Vec::new();
    for i in 0..3u8 {
        let m = GroupElement::random(&mut rng);
        attribute_messages.push(m);
        let b = ScalarNonZero::random(&mut rng);
        let c = ElGamal {
            gb: b * G,
            gc: m + b * *apk_from.value(),
        };
        put(out, &format!("AttributeM_{i}"), &m.to_hex());
        put(out, &format!("AttributeB_{i}"), &b.to_hex());
        put(out, &format!("AttributeV_{i}"), &ciphertext_hex(&c));
        attributes.push(EncryptedAttribute::from_value(c));
    }
    out.push('\n');

    let rekey_info = AttributeRekeyInfo::new(&session_from, &session_to, &enc_secret);
    put(out, "k_attribute", &rekey_info.k.scalar().to_hex());

    let rekeyed = rekey_batch(&mut attributes.clone(), &rekey_info, &apk_from, &mut rng)
        .expect("batch rekeying should succeed");

    for (i, c) in rekeyed.iter().enumerate() {
        put(
            out,
            &format!("AttributeOut_{i}"),
            &ciphertext_hex(c.value()),
        );
    }
    // Rekeying leaves the message unchanged, so each output decrypts to one of the inputs and
    // the permutation can be read off directly.
    let mut permutation = Vec::new();
    for (i, c) in rekeyed.iter().enumerate() {
        let p = c.value().gc - ask_to.value() * c.value().gb;
        put(out, &format!("AttributeP_{i}"), &p.to_hex());
        let source = (0..3)
            .find(|&j| attribute_messages[j] == p)
            .expect("every output attribute comes from one of the inputs");
        permutation.push(source.to_string());
    }
    put(out, "AttributePermutation", &permutation.join(","));
}

/// A session key share with its proof.
///
/// The share carries the ordinary rekey factor of the session: it is derived under the
/// ciphersuite like every other factor, so that a verifiable and a non-verifiable
/// transcryptor operating on the same session produce the same key material. What makes an
/// operation verifiable is the proof wrapped around the share, not the factor underneath; the
/// proof transcript is separated by its own labels, not by a protocol mode.
fn vectors_session_key_share(out: &mut String) {
    let mut rng = rng_for(0x03);

    let enc_secret = EncryptionSecret::from(b"transcryptor-1-encryption-secret".to_vec());
    let session = EncryptionContext::from("session-a");

    let k = make_pseudonym_rekey_factor(&enc_secret, &session);
    let k_commitment = k.scalar() * G;

    let b = ScalarNonZero::random(&mut rng);
    let blinding_commitment = BlindingCommitment::new(&b);
    let u = b * k.scalar();

    let proof = SessionKeyShareProof::new(&b, &k_commitment, &mut rng);

    out.push_str("// A session key share with its proof. K_c_1 is the ordinary rekey factor\n");
    out.push_str(
        "// commitment of the session, the same value as K_c above: the share is derived\n",
    );
    out.push_str("// under the ciphersuite, so a verifiable and a non-verifiable\n");
    out.push_str("// transcryptor on the same session agree on the key material. The proof\n");
    out.push_str("// transcript is separated by its own labels, not by a protocol mode.\n");
    out.push_str("// u_i is secret and is shown only so the vector can be reproduced.\n\n");

    put(out, "b_1", &b.to_hex());
    put(out, "B_1", &blinding_commitment.value().to_hex());
    put(out, "K_c_1", &k_commitment.to_hex());
    put(out, "u_1", &u.to_hex());
    put(out, "U_1", &proof.share_commitment().to_hex());

    assert!(
        proof.verify(&blinding_commitment, &k_commitment),
        "the session key share proof must verify"
    );
    assert_eq!(proof.share_commitment(), &(u * G), "U_1 must equal u_1 * G");
}

/// Build the whole vectors file.
fn generate() -> String {
    let ciphersuite = Ristretto255::CIPHERSUITE;

    let mut out = String::new();
    put(&mut out, "Ciphersuite", "ristretto255-SHA512");
    put(
        &mut out,
        "ContextString",
        &hex::encode(ciphersuite.context_string()),
    );
    put(&mut out, "Seed", &hex::encode(SEED));
    out.push('\n');

    out.push_str("\n// ===== DeriveFactor =====\n\n");
    vectors_derive_factor(&mut out);
    out.push_str("\n// ===== Single pseudonym =====\n\n");
    vectors_single_pseudonym(&mut out);
    out.push_str("\n// ===== Batch of three =====\n\n");
    vectors_batch(&mut out);
    out.push_str("\n// ===== Session key share =====\n\n");
    vectors_session_key_share(&mut out);

    out
}

/// Recompute every vector and assert each against its constant in `expected.rs`.
///
/// [`put`] does the per-value assertion, so a mismatch names the exact label that changed
/// instead of printing a whole-file diff.
#[test]
fn test_vectors_match_the_expected_constants() {
    let generated = generate();
    assert!(
        !generated.is_empty(),
        "the generator produced no vectors at all"
    );
}

/// Print the current vectors in the layout of `expected.rs`, for copying after an intended
/// change. Ignored by default, and asserts nothing:
///
/// ```text
/// cargo test --features batch,verifiable --test vectors -- --ignored --nocapture
/// ```
#[test]
#[ignore = "prints the vectors for copying into expected.rs; asserts nothing"]
fn print_vectors_for_copying() {
    CHECK.with(|c| c.set(false));
    println!("{}", generate());
}
