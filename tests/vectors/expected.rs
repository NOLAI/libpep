//! The expected test-vector values, one constant per line.
//!
//! Each constant holds the hex encoding of the value named in its doc comment.
//! `tests/vectors.rs` recomputes every one of them from the recorded seed and asserts
//! equality, so an unintended change to the hashing, the factor derivation, the
//! transcryption or the proofs fails the suite instead of passing silently.
//!
//! Names follow the protocol's own labels. Rust constants are upper-case, which would
//! collide a scalar with the group element of the same name (`k_c` and `K_c`), so scalars
//! carry a `SCALAR_` prefix and group elements keep the bare name.
//!
//! To update them after an intended change, run
//!
//! ```text
//! cargo test --features batch,verifiable --test vectors -- --ignored --nocapture
//! ```
//!
//! which prints the current values in this file's layout; copy the output here after
//! checking the diff value by value.

/// `Ciphersuite`
pub const CIPHERSUITE: &str = "ristretto255-SHA512";
/// `ContextString`
pub const CONTEXTSTRING: &str = "636f50524656312d72697374726574746f3235352d534841353132";
/// `Seed`
pub const SEED: &str = "6c69627065702d72697374726574746f3235352d5348413531322d7665632d31";

// ===== DeriveFactor =====

// DeriveFactor, the three labels of Table 1.
// The secrets are ASCII byte strings, shown here as hex.
/// `PS_1`
pub const PS_1: &str =
    "7472616e7363727970746f722d312d70736575646f6e796d697a6174696f6e2d736563726574";
/// `ES_1`
pub const ES_1: &str = "7472616e7363727970746f722d312d656e6372797074696f6e2d736563726574";
/// `DomainIdentifier`
pub const DOMAINIDENTIFIER: &str = "646f6d61696e2d61";
/// `SessionIdentifier`
pub const SESSIONIDENTIFIER: &str = "73657373696f6e2d61";
/// `labelRekeyPseudonym`
pub const SCALAR_LABELREKEYPSEUDONYM: &str = "01";
/// `k_c`
pub const SCALAR_K_C: &str = "70d5b3b5292a8db45d37f3ea19d72e11ac65a48d82b05cd184cdf906b944930b";
/// `K_c`
pub const K_C: &str = "e02076ebe02373bfc034edaef8a2569ff26ce589a8436b318a26e1f3a70dc560";
/// `labelRekeyAttribute`
pub const SCALAR_LABELREKEYATTRIBUTE: &str = "02";
/// `k'_c`
pub const SCALAR_K_PRIME_C: &str =
    "3b4c72d3eea7b6915144bfcb6e9198446e0663a318ebee76783c38233b537a05";
/// `K'_c`
pub const K_PRIME_C: &str = "680c39a2e1a372a129a8b75154cc827f6e22c813f2944a071e4541453d718918";
/// `labelReshuffle`
pub const SCALAR_LABELRESHUFFLE: &str = "03";
/// `s_d`
pub const SCALAR_S_D: &str = "48d30a5db673de12cd8a4c524739e029e73d2ec23017a50f653d422776d2bc0c";
/// `S_d`
pub const S_D: &str = "269f4bec48097732310c3c4d6d6d956e2189f046342e8c5a9efdfc3113c8182d";

// ===== Single pseudonym =====

// EncryptPseudonym / TranscryptPseudonym / Decrypt, one ciphertext.
// y is the global secret key; b is the encryption blinding scalar;
// r is the rerandomization scalar of the transcryption.
/// `Identifier`
pub const IDENTIFIER: &str = "70617469656e742d3432";
/// `M`
pub const M: &str = "9443144f8ff6b653c612fa635402ad3598a4e29ebf87eb8d964afcf5c13a3163";
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
pub const SCALAR_PK_FROM: &str = "1c937821ab471f8749460b52b4061fdc904f814d4d9e76d7440f459b131ef84d";
/// `b`
pub const SCALAR_B: &str = "232520f90a6508350126f42f4b04e7f26c1418ed7ac7f1ae789fc7553f22b904";
/// `V`
pub const V: &str = "e43bfa2c70155100b745294e18c76e6ab0cbc105b211f4a884f44b4f069e1027087ccf25ecbfdabf1407590d4380b62335744fe2c0588d3b3dcb4c4ba6950840";
/// `s`
pub const SCALAR_S: &str = "0e6febf1b89503f7ca630f39bec91e51415f5a86d054e10e09066fdbfc90730e";
/// `k`
pub const SCALAR_K: &str = "95408df0a4df432f1e82fb24b18084f6b69d313c05585c43c7b5c69f801c2407";
/// `r`
pub const SCALAR_R: &str = "3a778c5e60f053849173544065dce7808e65347c0a77ace6fee8c934ca18370d";
/// `V'`
pub const V_PRIME: &str = "aa5aca7202007bfd59c8e95b19818a17faf3a4bab1ca202a5d8081af9b430e2dbaf02a128186a023d3812dbaf63e7d0e228d79556a2fa46c7aca91c5ed176955";
/// `Y_to`
pub const Y_TO: &str = "64a4932e3fe087554059df526f279c029b94c027389a3b5e9ab365992bbbf524";
/// `P`
pub const P: &str = "d81b4bc1c5ded30bb710ae627a734e6b263bee2aeb0b708104ba77de3744d929";
/// `sk_to`
pub const SCALAR_SK_TO: &str = "6a4d402c45358f48ccc5ede5f1b7302766aac7fb0265bc93069e806eba04170a";

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
pub const PSEUDONYMM_0: &str = "ca8d9791d56f50e3bbeac7e42849e23a0b558d1cd53ff7a28e6e408a025e6103";
/// `PseudonymB_0`
pub const PSEUDONYMB_0: &str = "57b9dc9d1f93c84f917571e16cc5f5d924bade895d30569387d41d402ae87a05";
/// `PseudonymV_0`
pub const PSEUDONYMV_0: &str = "a8edd258e26a572d2302694ef9079d45d529cd4645ec29257f8ab791891c9837aa04e57f99f883bbb2d366ef15f2f4e39b296f3b601fb2f1fd4cdd7a2d7d7d71";
/// `PseudonymInput_1`
pub const PSEUDONYMINPUT_1: &str = "70617469656e742d32";
/// `PseudonymM_1`
pub const PSEUDONYMM_1: &str = "e00fc0d8dc482166b7d36df4dcd3c2f8dc8422ca308fd7891834d2cf34d97d4b";
/// `PseudonymB_1`
pub const PSEUDONYMB_1: &str = "f7fc4da3d3984af314d278dff7a06b4a4ffa3319bcb4ced72f10e25757985503";
/// `PseudonymV_1`
pub const PSEUDONYMV_1: &str = "fcb594cb294c7d18ed058658ba577a28eec42e044e5acb84c0560043a13140117c945871b119b8ba62969d0fed4fde919fe80d097202c420eea042cf70a8354e";
/// `PseudonymInput_2`
pub const PSEUDONYMINPUT_2: &str = "70617469656e742d33";
/// `PseudonymM_2`
pub const PSEUDONYMM_2: &str = "d6a6568823286edeb5a591a8ee3280cb871eeaa870ae89bc6b4c7589526a540b";
/// `PseudonymB_2`
pub const PSEUDONYMB_2: &str = "7d594cbae2df704390e98f567cf10cc194d392cf89cb2d70bfc449a5f0c5fd0c";
/// `PseudonymV_2`
pub const PSEUDONYMV_2: &str = "38d06fca356dee46ece18ce53518c4b094167a7b3f339595c25b45949c09e47782458ce71edd69fb4043102073c018fc0ae2aa9fddcc0b5876376d21d4830c6c";
/// `PseudonymOut_0`
pub const PSEUDONYMOUT_0: &str = "08d523cbc988ae53b55037d76491344d75257244dc859fc9d9a9f72ff39d0647b02d8acd343a14d839341151ab58ac7d8184230ef3e0bed0b5606161f42e7c32";
/// `PseudonymOut_1`
pub const PSEUDONYMOUT_1: &str = "286eaef85fe205addce8d7ab3614af6a0140a54df4248ea549b299fd6df7de2afeb650a5f2df3dd35cf918b8488d9923c42afea40387b4c20f274cba1bdca848";
/// `PseudonymOut_2`
pub const PSEUDONYMOUT_2: &str = "ee2ad84bada8601cdd99bcc8e58549488da90ee939a36e33052c49adb65f032e62c7e385a49ca9512b849a4a0a4a0a9b1acaa05be178324dd6622a75121d0225";
/// `PseudonymP_0`
pub const PSEUDONYMP_0: &str = "7e6da74d1804fbfa3fbfdbae3be7a8eb4583ac8216b68a7112a333b78f1ba879";
/// `PseudonymP_1`
pub const PSEUDONYMP_1: &str = "868ef3a059cf1fc6ab1fc7c3ed60472ae5fd354f777a809515c5162a538d9e26";
/// `PseudonymP_2`
pub const PSEUDONYMP_2: &str = "505c3ed908dd214123e0ae9db072641b1734c079d45853487445b647ecc5114b";
/// `PseudonymPermutation`
pub const PSEUDONYMPERMUTATION: &str = "2,0,1";
/// `AttributeM_0`
pub const ATTRIBUTEM_0: &str = "c239ba10c2cb7dbe363124bec3be7d0d898ab78470e1b471ad92fcca550e9321";
/// `AttributeB_0`
pub const ATTRIBUTEB_0: &str = "7ff2a46fda994c67e247a9a23f053c422b23d343a185b9c3467b791bfde8d405";
/// `AttributeV_0`
pub const ATTRIBUTEV_0: &str = "12c7a68d8d4279b6ff17e517e10a304442318e075c7a7f5eca06fe35549c4624c82daf6e35d66249d91d3bfd70b4f06c6dc91fad73e2a5561d51e7935d419632";
/// `AttributeM_1`
pub const ATTRIBUTEM_1: &str = "f25d853f29cb794ba7da5e52c8c548dbdae6c21ddc09ffe17fb54e71500e3d7b";
/// `AttributeB_1`
pub const ATTRIBUTEB_1: &str = "54c0fd66874e0f08eeb4d58093d0b58c43c035ea108d7772b6f8f3695251a30f";
/// `AttributeV_1`
pub const ATTRIBUTEV_1: &str = "7a7b822ec72e16b75bf717f54998bed1eccbfb0871d3764230b9a73b2913127176c0b2837f226126d3fe11ba08aa4881e7a91d5703eae3e1d1fcccd77ffaf026";
/// `AttributeM_2`
pub const ATTRIBUTEM_2: &str = "ccb89ef69f031f7254bbb447fdecd4269f4f00b93bebfb2e9b1eca92df03336e";
/// `AttributeB_2`
pub const ATTRIBUTEB_2: &str = "8bc9e1ff43f79c3702807e3caa641c3e51e7e1db8b76227307a0ae6d8f7da60b";
/// `AttributeV_2`
pub const ATTRIBUTEV_2: &str = "1425a836a0ec527bde77e1ec4f98baae5ddede709d2fc5b19a0399ad60375718406eb119f32ce2b64a6c9bdbe2ce35864537de6dcd7270d265789df10d039b16";
/// `k_attribute`
pub const SCALAR_K_ATTRIBUTE: &str =
    "cdfd3672876a7d530711e959d60e553b3dc499b9d3e666f5f3792d541cb51a08";
/// `AttributeOut_0`
pub const ATTRIBUTEOUT_0: &str = "9cad1fa49038541fec4e05897106279d3886f37b23af74a6e15903a095f995400a17fd153d3b851ce9f51dda396d520f34d94072dfc34f4258b1ca64c4728d68";
/// `AttributeOut_1`
pub const ATTRIBUTEOUT_1: &str = "a072e3e4b0e39f302064b3ac26ef6458e3bdca8338b861457385ba74a789dd784628e3c748eb9828447571c57487c151e8caa27c145b19e8a253a6eb813c2b2f";
/// `AttributeOut_2`
pub const ATTRIBUTEOUT_2: &str = "f0b257978939f2fba6d397f5a2159bb839538364345f1fddd4a6992c6c201b583cf07ff500304c9d79f081a9dea6412cf77b644859150765e5c0cca2a414c531";
/// `AttributeP_0`
pub const ATTRIBUTEP_0: &str = "c239ba10c2cb7dbe363124bec3be7d0d898ab78470e1b471ad92fcca550e9321";
/// `AttributeP_1`
pub const ATTRIBUTEP_1: &str = "ccb89ef69f031f7254bbb447fdecd4269f4f00b93bebfb2e9b1eca92df03336e";
/// `AttributeP_2`
pub const ATTRIBUTEP_2: &str = "f25d853f29cb794ba7da5e52c8c548dbdae6c21ddc09ffe17fb54e71500e3d7b";
/// `AttributePermutation`
pub const ATTRIBUTEPERMUTATION: &str = "0,2,1";

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
pub const K_C_1: &str = "e02076ebe02373bfc034edaef8a2569ff26ce589a8436b318a26e1f3a70dc560";
/// `u_1`
pub const SCALAR_U_1: &str = "b4f3a40f57788fe8898e3e6e7978ff2568809e3754ebca6d82d01ab94dc7d20a";
/// `U_1`
pub const U_1: &str = "b4701454d81777f4ffb776046e9c440526e43c563d75d922365ce0cbe1b08979";
