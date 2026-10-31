//! Test vectors for the ristretto255-SHA512 ciphersuite.
//!
//! The expected values live as Rust constants in `the `expected` module of `tests/vectors.rs``, one per line, and
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
//! which prints the current values in the layout of the `expected` module; copy the output there after
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

mod common;

use common::aliases::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use common::aliases::{AttributeRekeyInfo, PseudonymizationInfo};
use common::aliases::{BlindingCommitment, SessionKeyShareProof};
use common::aliases::{EncryptedAttribute, EncryptedPseudonym};
use libpep::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::data::simple::ElGamalEncrypted;
use libpep::elgamal::arithmetic::group_elements::{GroupElement, G};
use libpep::elgamal::arithmetic::hashing::hash_to_group;
use libpep::elgamal::arithmetic::scalars::{ScalarNonZero, ScalarTraits};
use libpep::elgamal::arithmetic::{Ciphersuite, Ristretto255, Ristretto255Sha512};
use libpep::elgamal::ElGamal;
use libpep::factors::derivation::{LABEL_REKEY_ATTRIBUTE, LABEL_REKEY_PSEUDONYM, LABEL_RESHUFFLE};
use libpep::factors::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, make_pseudonymization_factor,
};
use libpep::factors::{EncryptionSecret, Factor, PseudonymizationSecret};
use libpep::keys::traits::{PublicKey, SecretKey};
use libpep::keys::{make_attribute_session_keys, make_pseudonym_session_keys};
use libpep::transcryptor::{pseudonymize_batch, rekey_batch};
use rand::rngs::ChaCha20Rng;
use rand::SeedableRng;
use std::fmt::Write as _;

/// The expected test-vector values, one constant per line.
///
/// Each constant holds the hex encoding of the value named in its doc comment.
/// `tests/vectors.rs` recomputes every one of them from the recorded seed and asserts
/// equality, so an unintended change to the hashing, the factor derivation, the
/// transcryption or the proofs fails the suite instead of passing silently.
///
/// Names follow the protocol's own labels. Rust constants are upper-case, which would
/// collide a scalar with the group element of the same name (`k_c` and `K_c`), so scalars
/// carry a `SCALAR_` prefix and group elements keep the bare name.
///
/// To update them after an intended change, run
///
/// ```text
/// cargo test --features batch,verifiable --test vectors -- --ignored --nocapture
/// ```
///
/// which prints the current values in this file's layout; copy the output here after
/// checking the diff value by value.
#[rustfmt::skip]
mod expected {
    /// `Ciphersuite`
    pub const CIPHERSUITE: &str = "ristretto255-SHA512";
    /// `ContextString`
    pub const CONTEXTSTRING: &str = "6e50455056312d72697374726574746f3235352d534841353132";
    /// `Seed`
    pub const SEED: &str = "6c69627065702d72697374726574746f3235352d5348413531322d7665632d31";


    // ===== DeriveFactor =====

    // DeriveFactor, the three labels of Table 1.
    // The secrets are ASCII byte strings, shown here as hex.

    /// `PS_1`
    pub const PS_1: &str = "7472616e7363727970746f722d312d70736575646f6e796d697a6174696f6e2d736563726574";
    /// `ES_1`
    pub const ES_1: &str = "7472616e7363727970746f722d312d656e6372797074696f6e2d736563726574";
    /// `DomainIdentifier`
    pub const DOMAINIDENTIFIER: &str = "646f6d61696e2d61";
    /// `SessionIdentifier`
    pub const SESSIONIDENTIFIER: &str = "73657373696f6e2d61";

    /// `labelRekeyPseudonym`
    pub const SCALAR_LABELREKEYPSEUDONYM: &str = "01";
    /// `k_c`
    pub const SCALAR_K_C: &str = "9e1063dfacc4da6b89565e9fd97543433d2856765c311d00b1a714f213b2d308";
    /// `K_c`
    pub const K_C: &str = "a2c04b4513c51654575727d906f54d8e9d4932b98014d489ae5c0f66293a1f03";

    /// `labelRekeyAttribute`
    pub const SCALAR_LABELREKEYATTRIBUTE: &str = "02";
    /// `k'_c`
    pub const SCALAR_K_PRIME_C: &str = "233b4879c55f58c4cad13fa52245fa793d9f3fa02ba1e28281cd3000605b650d";
    /// `K'_c`
    pub const K_PRIME_C: &str = "d490876938e82b115871d3b45763d3043530c9306d5e5041eba736f06358337a";

    /// `labelReshuffle`
    pub const SCALAR_LABELRESHUFFLE: &str = "03";
    /// `s_d`
    pub const SCALAR_S_D: &str = "7ad6409b47f6664fd9c3fbc1b9c45dad0fcd01f54c8533517b875de90de9e404";
    /// `S_d`
    pub const S_D: &str = "f052c54006ddf0647da052c57e7732ecda11749c1df8282210eaa6b74c1cd16a";

    // ===== Single pseudonym =====

    // EncryptPseudonym / TranscryptPseudonym / Decrypt, one ciphertext.
    // y is the global secret key; b is the encryption blinding scalar;
    // r is the rerandomization scalar of the transcryption.

    /// `Identifier`
    pub const IDENTIFIER: &str = "70617469656e742d3432";
    /// `M`
    pub const M: &str = "00191151a59a9dd40a4f9ab5d9c99be793ddff916e9b9d7238a3ab4e359aec07";
    /// `y`
    pub const SCALAR_Y: &str = "f60c0ff0af9a5212ea4294c5f4184fcd8758c32c54bddee2c6aed4238a31270c";
    /// `Y`
    pub const Y: &str = "52c70793c33b4703c4970f71d4f7612e6b8bdb137a8ed363125e3b9eb8912f16";
    /// `DomainFrom`
    pub const DOMAINFROM: &str = "646f6d61696e2d61";
    /// `DomainTo`
    pub const DOMAINTO: &str = "646f6d61696e2d62";
    /// `SessionFrom`
    pub const SESSIONFROM: &str = "73657373696f6e2d61";
    /// `SessionTo`
    pub const SESSIONTO: &str = "73657373696f6e2d62";
    /// `pk_from`
    pub const SCALAR_PK_FROM: &str = "7ed1d7f1f90401133709a5c65d5b8a564c6943f6cbeca39bb3381e03f53aec04";
    /// `b`
    pub const SCALAR_B: &str = "232520f90a6508350126f42f4b04e7f26c1418ed7ac7f1ae789fc7553f22b904";
    /// `V`
    pub const V: &str = "e43bfa2c70155100b745294e18c76e6ab0cbc105b211f4a884f44b4f069e102756228635e652053bc0cbb41449f38cf583af9e9217e35cb6e45ca14a90b4af5b";

    /// `s`
    pub const SCALAR_S: &str = "8330955409c994b9f5345c9c4788ce61f278351ad9cb6f2f21ffada70b509a01";
    /// `k`
    pub const SCALAR_K: &str = "4764ef625f74fd5d148a2d4e6a0bc43be07e4dfccb3b0ef381c0952cd42f0a04";
    /// `r`
    pub const SCALAR_R: &str = "3a778c5e60f053849173544065dce7808e65347c0a77ace6fee8c934ca18370d";
    /// `V'`
    pub const V_PRIME: &str = "f8ae7c6ea3d30fba07e1788610bd3880cf91bbb6231fcec449a2a56f8b250f180ecef7fc5c3ca8741a84b74914359209cb5790d5e01693814c9d7ff45ca1dd6e";
    /// `Y_to`
    pub const Y_TO: &str = "8cac918bf6e8b6d9808b11e9db1f55be0346936725658bd18c4af50b6d2e866c";

    /// `P`
    pub const P: &str = "5ca238c0e468a5047cdb9f36159c7d3c6aa7479f499356a5463a3d75adf3696e";
    /// `sk_to`
    pub const SCALAR_SK_TO: &str = "b46dd218345aa5adf1f665900a90df3d3cb83553df7e1937c673985d90f1780d";

    // ===== Batch of three =====

    // A batch of three pseudonyms (typePseudonym, 0x01) and three attributes
    // (typeAttribute, 0x02). The permutation and every r are drawn from the
    // recorded seed with stream label 02, so the output order is reproducible.

    /// `BatchSeed`
    pub const BATCHSEED: &str = "6c69627065702d72697374726574746f3235352d5348413531322d7665632d02";
    /// `typePseudonym`
    pub const SCALAR_TYPEPSEUDONYM: &str = "01";
    /// `typeAttribute`
    pub const SCALAR_TYPEATTRIBUTE: &str = "02";

    /// `PseudonymInput_0`
    pub const PSEUDONYMINPUT_0: &str = "70617469656e742d31";
    /// `PseudonymM_0`
    pub const PSEUDONYMM_0: &str = "3c750759cc3582101060d574636cea9cbc935181bde2821312fbfee91c957546";
    /// `PseudonymB_0`
    pub const PSEUDONYMB_0: &str = "57b9dc9d1f93c84f917571e16cc5f5d924bade895d30569387d41d402ae87a05";
    /// `PseudonymV_0`
    pub const PSEUDONYMV_0: &str = "a8edd258e26a572d2302694ef9079d45d529cd4645ec29257f8ab791891c983712b7028f759ec15929ef4d0e5fdaba099068f1946cb5b5f9d3f24e07df08257f";
    /// `PseudonymInput_1`
    pub const PSEUDONYMINPUT_1: &str = "70617469656e742d32";
    /// `PseudonymM_1`
    pub const PSEUDONYMM_1: &str = "9c20f48d7ea00873fba3e26d83a0f847e95078ffdfaba1f024ad0418899c2f42";
    /// `PseudonymB_1`
    pub const PSEUDONYMB_1: &str = "f7fc4da3d3984af314d278dff7a06b4a4ffa3319bcb4ced72f10e25757985503";
    /// `PseudonymV_1`
    pub const PSEUDONYMV_1: &str = "fcb594cb294c7d18ed058658ba577a28eec42e044e5acb84c0560043a1314011a2e1b4aad1712885cbc08ace2f2b0d39b74ed8a4e7e46904b42cb7338527584f";
    /// `PseudonymInput_2`
    pub const PSEUDONYMINPUT_2: &str = "70617469656e742d33";
    /// `PseudonymM_2`
    pub const PSEUDONYMM_2: &str = "94508e154ef88d683d903c6a8031b83b67379b3a0326e1e6f0846129e1babc60";
    /// `PseudonymB_2`
    pub const PSEUDONYMB_2: &str = "7d594cbae2df704390e98f567cf10cc194d392cf89cb2d70bfc449a5f0c5fd0c";
    /// `PseudonymV_2`
    pub const PSEUDONYMV_2: &str = "38d06fca356dee46ece18ce53518c4b094167a7b3f339595c25b45949c09e47764380ae19024abb11d2e323ecc45de44b55a56326a22238563f89b03f3b40c16";

    /// `PseudonymOut_0`
    pub const PSEUDONYMOUT_0: &str = "f067bfdf1803c057a11924351476612b2f691942d592d0e1bdecd35d2effec03f406d632fb3efa3fd1d9a6a17f3534990c5351d4042aa068f3449c429cc2287c";
    /// `PseudonymOut_1`
    pub const PSEUDONYMOUT_1: &str = "ba50872490dddab0c28e62a13abe2dfb2aac92bff6195c06add703a6188fe821e68f28f3fdb02896c83a36a00fa743bea76b7c5862f74aae3cc322ec3c52e864";
    /// `PseudonymOut_2`
    pub const PSEUDONYMOUT_2: &str = "08e416c6a560fa695b5696de64acd5370b9260940e023b6e502b8b2cc3ce1c652e5cc764a6c928a458ea0d58d3b5efad5935b0e79256be9cbd85f643ed13515f";
    /// `PseudonymP_0`
    pub const PSEUDONYMP_0: &str = "ec8c1d0d0c625da643e6d7875e99c15148ae203fa248f88939ca6b7ec5972973";
    /// `PseudonymP_1`
    pub const PSEUDONYMP_1: &str = "b8bf966e67930545e2bb0149c9b1dab887273d40a249a558887700ce5932ff68";
    /// `PseudonymP_2`
    pub const PSEUDONYMP_2: &str = "facb92b2e578f6cdb7a80c0781902e78efc76829829529fa16a467ab15e86b73";
    /// `PseudonymPermutation`
    pub const PSEUDONYMPERMUTATION: &str = "0,1,2";

    /// `AttributeM_0`
    pub const ATTRIBUTEM_0: &str = "c239ba10c2cb7dbe363124bec3be7d0d898ab78470e1b471ad92fcca550e9321";
    /// `AttributeB_0`
    pub const ATTRIBUTEB_0: &str = "7ff2a46fda994c67e247a9a23f053c422b23d343a185b9c3467b791bfde8d405";
    /// `AttributeV_0`
    pub const ATTRIBUTEV_0: &str = "12c7a68d8d4279b6ff17e517e10a304442318e075c7a7f5eca06fe35549c46242c8f5e0803d202f03c0b9cd41753060f09fbfd5d085bcc9b576ce559046ed10d";
    /// `AttributeM_1`
    pub const ATTRIBUTEM_1: &str = "f25d853f29cb794ba7da5e52c8c548dbdae6c21ddc09ffe17fb54e71500e3d7b";
    /// `AttributeB_1`
    pub const ATTRIBUTEB_1: &str = "54c0fd66874e0f08eeb4d58093d0b58c43c035ea108d7772b6f8f3695251a30f";
    /// `AttributeV_1`
    pub const ATTRIBUTEV_1: &str = "7a7b822ec72e16b75bf717f54998bed1eccbfb0871d3764230b9a73b291312717ca2df6c05668030b731bf68520758b6e06a1c7bf722d0113bd86195c0a11f77";
    /// `AttributeM_2`
    pub const ATTRIBUTEM_2: &str = "ccb89ef69f031f7254bbb447fdecd4269f4f00b93bebfb2e9b1eca92df03336e";
    /// `AttributeB_2`
    pub const ATTRIBUTEB_2: &str = "8bc9e1ff43f79c3702807e3caa641c3e51e7e1db8b76227307a0ae6d8f7da60b";
    /// `AttributeV_2`
    pub const ATTRIBUTEV_2: &str = "1425a836a0ec527bde77e1ec4f98baae5ddede709d2fc5b19a0399ad6037571866a6f5955e8f5670ef7014c918cdadb943a6889f90963ca98876cacbabf97650";

    /// `k_attribute`
    pub const SCALAR_K_ATTRIBUTE: &str = "40cf146efdc310243fbaa0ec1195a311339185b64d212990177ff7fa4ba22e03";
    /// `AttributeOut_0`
    pub const ATTRIBUTEOUT_0: &str = "ba7d1a467b476e8cdebde57e58d50649de4b6532787a5742407ba35a1b283f6b68937518c730e2ff518a13ee056e2c82ea881ffaa2ff88ce06eeebcc5be42f61";
    /// `AttributeOut_1`
    pub const ATTRIBUTEOUT_1: &str = "e8d404259cb2759fd644cdabe84af35c0736978d1661b0565a08ed81a315b125ac44384dda5d3e1411af4d2365b9f6b2580c065ff4f4de7158cb8dcd1b5b730c";
    /// `AttributeOut_2`
    pub const ATTRIBUTEOUT_2: &str = "0c5143c4af16c1eb1f6da36ca11c953b8adc6f910e089471deb3c0533483bc17149a8fdc701889cc84e254c756000d14f36c122b237e78597e56c0f3aaa25a47";
    /// `AttributeP_0`
    pub const ATTRIBUTEP_0: &str = "ccb89ef69f031f7254bbb447fdecd4269f4f00b93bebfb2e9b1eca92df03336e";
    /// `AttributeP_1`
    pub const ATTRIBUTEP_1: &str = "f25d853f29cb794ba7da5e52c8c548dbdae6c21ddc09ffe17fb54e71500e3d7b";
    /// `AttributeP_2`
    pub const ATTRIBUTEP_2: &str = "c239ba10c2cb7dbe363124bec3be7d0d898ab78470e1b471ad92fcca550e9321";
    /// `AttributePermutation`
    pub const ATTRIBUTEPERMUTATION: &str = "2,1,0";

    // ===== Session key share =====

    // A session key share with its proof. K_c_1 is the ordinary rekey factor
    // commitment of the session, the same value as K_c above: the share is derived
    // under the ciphersuite, so a verifiable and a non-verifiable
    // transcryptor on the same session agree on the key material. The proof
    // transcript is separated by its own labels, not by a protocol mode.
    // u_i is secret and is shown only so the vector can be reproduced.

    /// `b_1`
    pub const SCALAR_B_1: &str = "17dc8b002247c4b99d56d8f4a5ec806c6551f72f67d2c3e2e8d06bfa8854db05";
    /// `B_1`
    pub const B_1: &str = "ca2459c021f08341da7d44ebc35456686ec2f97b91e6fcc1ae50fa874599cd1e";
    /// `K_c_1`
    pub const K_C_1: &str = "a2c04b4513c51654575727d906f54d8e9d4932b98014d489ae5c0f66293a1f03";
    /// `u_1`
    pub const SCALAR_U_1: &str = "92d081fa00b670576bf7a8ce3208b2974f4bf5a6108609c1d67742c3ebd82705";
    /// `U_1`
    pub const U_1: &str = "e856108b5eda788634c05bc6436ffbaf53a1e4de085d8a64d6ff0554a6e74c71";
}

/// The seed of every ChaCha20 RNG used below, recorded as [`expected::SEED`].
const SEED: [u8; 32] = *b"libpep-ristretto255-SHA512-vec-1";

/// A ChaCha20 RNG seeded with [`SEED`] and a one-byte stream label, so that each vector group
/// draws from its own reproducible stream.
fn rng_for(label: u8) -> ChaCha20Rng {
    let mut seed = SEED;
    seed[31] = label;
    ChaCha20Rng::from_seed(seed)
}

fn ciphertext_hex(c: &ElGamal<Ristretto255>) -> String {
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
            panic!("no expected constant for {name}; add it to the `expected` module of `tests/vectors.rs`")
        })
}

/// Record a computed value and check it against its constant.
///
/// `out` collects the values in the layout of the `expected` module, so that the ignored
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
            "{name} differs from the `expected` module of `tests/vectors.rs`. If this change is intended, \
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

    let k = make_pseudonym_rekey_factor::<Ristretto255Sha512>(&enc_secret, &session);
    put(
        out,
        "labelRekeyPseudonym",
        &format!("{LABEL_REKEY_PSEUDONYM:02x}"),
    );
    put(out, "k_c", &k.scalar().to_hex());
    put(out, "K_c", &(k.scalar() * G).to_hex());
    out.push('\n');

    let ka = make_attribute_rekey_factor::<Ristretto255Sha512>(&enc_secret, &session);
    put(
        out,
        "labelRekeyAttribute",
        &format!("{LABEL_REKEY_ATTRIBUTE:02x}"),
    );
    put(out, "k'_c", &ka.scalar().to_hex());
    put(out, "K'_c", &(ka.scalar() * G).to_hex());
    out.push('\n');

    let s = make_pseudonymization_factor::<Ristretto255Sha512>(&pseudo_secret, &domain);
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

    let (pk_from, _sk_from) = make_pseudonym_session_keys::<Ristretto255Sha512>(
        &global_secret,
        &session_from,
        &enc_secret,
    );
    let (_pk_to, sk_to) =
        make_pseudonym_session_keys::<Ristretto255Sha512>(&global_secret, &session_to, &enc_secret);

    // The identifier is encoded with hash_to_group.
    let identifier = b"patient-42";
    let m = hash_to_group::<Ristretto255Sha512>(identifier);

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
    let info = PseudonymizationInfo::new::<Ristretto255Sha512>(
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
    let rerandomized = ElGamal::<Ristretto255> {
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

    let (pk_from, _) = make_pseudonym_session_keys::<Ristretto255Sha512>(
        &pseudonym_global,
        &session_from,
        &enc_secret,
    );
    let (_, sk_to) = make_pseudonym_session_keys::<Ristretto255Sha512>(
        &pseudonym_global,
        &session_to,
        &enc_secret,
    );
    let (apk_from, _) = make_attribute_session_keys::<Ristretto255Sha512>(
        &attribute_global,
        &session_from,
        &enc_secret,
    );
    let (_, ask_to) = make_attribute_session_keys::<Ristretto255Sha512>(
        &attribute_global,
        &session_to,
        &enc_secret,
    );

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
        let m = hash_to_group::<Ristretto255Sha512>(id);
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

    let info = PseudonymizationInfo::new::<Ristretto255Sha512>(
        &domain_from,
        &domain_to,
        &session_from,
        &session_to,
        &pseudo_secret,
        &enc_secret,
    );

    let transcrypted = pseudonymize_batch(&pseudonyms.clone(), &info, &pk_from, &mut rng)
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
            .find(|&j| s * hash_to_group::<Ristretto255Sha512>(identifiers[j]) == p)
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

    let rekey_info =
        AttributeRekeyInfo::new::<Ristretto255Sha512>(&session_from, &session_to, &enc_secret);
    put(out, "k_attribute", &rekey_info.k.scalar().to_hex());

    let rekeyed = rekey_batch(&attributes.clone(), &rekey_info, &apk_from, &mut rng)
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

    let k = make_pseudonym_rekey_factor::<Ristretto255Sha512>(&enc_secret, &session);
    let k_commitment = k.scalar() * G;

    let b = ScalarNonZero::random(&mut rng);
    let blinding_commitment = BlindingCommitment::new(&b);
    let u = b * k.scalar();

    let proof = SessionKeyShareProof::new::<Ristretto255Sha512, _>(&b, &k_commitment, &mut rng);

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
        proof.verify::<Ristretto255Sha512>(&blinding_commitment, &k_commitment),
        "the session key share proof must verify"
    );
    assert_eq!(proof.share_commitment(), &(u * G), "U_1 must equal u_1 * G");
}

/// Build the whole vectors file.
fn generate() -> String {
    let ciphersuite = Ristretto255Sha512::ID;

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

/// Recompute every vector and assert each against its constant in the `expected` module.
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

/// Print the current vectors in the layout of the `expected` module, for copying after an intended
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
