# Changelog

## Unreleased (0.14.0)

The crate version is bumped to 0.14.0: the security fixes below change the
signatures of the transcryption operations, which `cargo semver-checks` flags as
a major change against the published 0.13.0.

### API changes

- `PseudonymizationDomain`, `EncryptionContext`, `PseudonymizationSecret` and `EncryptionSecret`
  implement `From` (`&str` and `String`; `&[u8]`, `Vec<u8>` and `Box<[u8]>`) instead of an
  inherent `from`, so `"x".into()` works and the secrets expose `as_bytes`.
- The four factor types implement one `factors::Factor` trait (`from_scalar`, `scalar`); the
  `RekeyFactor` trait is gone. The public key a ciphertext is encrypted under after a
  transcryption is given by the `factors::RekeyPublicKey` trait, implemented by every info for the
  key of the data it transcrypts; `TranscryptionInfo::rekey_public_keys` is now `rekey_public_key`,
  and the `convert` methods on session public keys are gone.
- `ElGamalEncryptable::from_value` is gone; `from_point` is the constructor, as for public keys.
- `Client::dump` is `Client::keys`; `Client::restore` and `DistributedTranscryptor::system` are gone
  (`new` and `Deref` do the same). `OfflineClient::encrypt_batch` is gone: values encrypted
  towards the global keys are not a session batch; `encrypt_global_batch` remains and returns a
  `Vec`, as do `encrypt_batch_raw` and `decrypt_global_batch`.
- The `EncryptedBatch` operations are generic over the encrypted type and infallible (the
  structure is validated on construction); the slice functions `pseudonymize_batch`, `rekey_batch`
  and `transcrypt_batch` return a `Vec`. The unused `BatchEncryptable` trait is gone; batch
  preprocessing is `Encryptable::preprocess_for_batch`.
- Padding and parsing errors are typed: `data::padding::PaddingError` replaces `std::io::Error`
  in the padded encodings and `pad_to`, `errors::ParseError` in the string decoders of long
  encrypted values and records, and `JsonError` wraps a `PaddingError` instead of a string.
  `CacheRegistrationError` and `ZeroArgumentError` are `thiserror` errors.
- Names: `make_pseudonymisation_factor` is `make_pseudonymization_factor`, and
  `Transcryptor::pseudonymisation_secret` is `pseudonymization_secret`, in Rust and the bindings.
  `PEPJSONValue`, `EncryptedPEPJSONValue`, `PEPJSONBuilder` and `JSONStructure` are
  `PepJsonValue`, `EncryptedPepJsonValue`, `PepJsonBuilder` and `JsonStructure`; the Python and
  JavaScript classes follow. `data::json::utils` (the byte encodings of JSON booleans and numbers)
  is public.
- The verifiable commitments expose their group element through `point()` and are built from
  the transcryption infos with `From` (`VerifiablePseudonymizationCommitment::from(info)` and
  so on).
- The verifiable layer is generic over the group, like the rest of the library: the proof
  types of `elgamal::verifiable`, `elgamal::zkps` and `elgamal::dleq`, the commitments, the
  Carter–Wegman master keys, the session key share proofs, the data-layer proofs and the
  `Verifier` all have a `G: Group` version in a `generic` submodule, and the names at the module
  level are their ristretto255 instances. For this, `Group` gained `ScalarCanBeZero`, the scalar
  field with its addition, and its encoding functions, and `hashing::hash_to_nonzero_scalar`, the
  group's hash reduced to a non-zero scalar. Proof bytes on ristretto255 are unchanged.
- The batch proofs of the data layer are three types generic over the item type,
  `BatchPseudonymizationProof<E>`, `BatchRekeyProof<E>` and `BatchTranscryptionProof<E>` in
  `data::verifiable::batch`, built on the `VerifiableBatchItem` trait that lays an item's
  ciphertexts out in a list; the per-type names (`PseudonymPseudonymizationBatchProof`,
  `RecordTranscryptionBatchProof`, ...) are aliases of them. The record batch proofs no longer
  carry a `structure` field, and every batch of a transcryptable type has
  `verifiable_transcrypt`. The data-layer proofs expose their `verify`,
  `verified_reconstruct` and `unverified_reconstruct` only through the `Verifiable*Proof`
  traits; the inherent duplicates are gone.
- `zkps::Proof` encodes with `to_bytes`/`from_slice` (and `LENGTH`) like the other types,
  instead of `encode`/`decode`/`decode_from_slice` on a fixed array; `dleq::Proof` likewise
  returns a `Vec`. `JSONTranscryptionProof` and `VerifiableJSONBatch` are `JsonTranscryptionProof`
  and `JsonTranscryptionBatchProof`.
- `elgamal::zkps` no longer carries the unused signature functions (`sign`, `verify`,
  `sign_unlinkable`, `create_proof_unlinkable`).
- The `verifier::verifier` module is merged into `verifier`.
- Every public item is documented (`missing_docs` warns).
- In the JavaScript bindings, `fromHash` returns `undefined` for input that is not 64 bytes
  instead of aborting.

### Security

- Session key share verification did not bind the received scalar to the proof.
  `SessionKeyShareProof::verify` checks the ZKP against the blinding and rekey commitments, but
  it never sees the share scalar `u_i`, so a transcryptor could hand over a valid proof alongside
  an unrelated share and nothing would catch it. `verify_share` (and `matches_share`) additionally
  check `U_i == u_i · G`, as the WPES '26 paper requires; `verify` remains for verifiers that hold
  only public values and now documents what it does not establish. Exposed in Python as
  `verify_share` and in JavaScript as `verifyPseudonymShare` / `verifyAttributeShare`.
- Every transcryption now rerandomizes the ciphertext before applying the reshuffle and rekey
  factors (RRSK/RRK). Previously the high-level `pseudonymize`, `rekey` and `transcrypt` (and the
  batch variants) applied the factors only, so a malicious sender could place a pseudonym directly
  in a malformed ciphertext and obtain the receiver's pseudonym in the clear.
- The batch shuffle uses unbiased index sampling.
- `GroupElement::from_bytes`, `from_slice` and `from_hex` reject the identity element.
- Factor derivation rejects a factor equal to 1 as well as 0 (derived factors are unchanged in the
  non-degenerate case).

### Breaking changes

- The minimum supported Rust version is 1.88, up from 1.85. Transitive dependencies of
  `curve25519-dalek`, `sha2` and `hmac` raised their own floors during this cycle: `ctutils`
  0.4.3 requires 1.87 and `sha2` 0.11.1 requires 1.88.
- Verifiable operations and the verifiable batch types take `SessionPublicKeys` where they
  previously took `SessionKeys`: verification and batch transport need only the public halves.
  This affects `verified_reconstruct_batch`, `verified_reconstruct_transcryption`,
  `verifiable_transcrypt` and the batch constructors, in Rust and in both bindings. In
  JavaScript the `EncryptedBatch` constructors, their `publicKey()` getter and `transcrypt()`
  now use `SessionPublicKeys`; call `SessionKeys.public()` to obtain one.

- Factor derivation follows `DeriveFactor` of draft-doesburg-cfrg-coprf: `HashToScalar`
  (RFC 9497, ristretto255-SHA512: `expand_message_xmd` with SHA-512, RFC 9380) over the
  length-prefixed secret, the label and the length-prefixed identifier, with domain separation tag
  `"DeriveFactor-" || contextString`, rejecting 0 and 1 with a counter. **Derived factors and
  session keys change**, and the HMAC-SHA512 derivation of 0.13 is gone: `DeriveFactor` is the
  only derivation outside `legacy`, which is unchanged and still reproduces the PEP repository
  implementation bit for bit.
- A `Ciphersuite` (`elgamal::arithmetic::Ciphersuite`: the ciphersuite identifier, context string
  `"coPRFV1-" || identifier`) domain-separates the protocol's hashes. An identifier names a group
  *and* a hash (`ristretto255-SHA512`), so it belongs to the group: it is the associated constant
  `Group::CIPHERSUITE`, taken verbatim from the draft's ciphersuite table, and cannot be
  constructed from an arbitrary string. One group's identifier therefore cannot be paired with
  another group's operations. The type is `Copy` and const-constructible, and its context string
  is a `&'static [u8]`, so neither factor derivation nor hashing allocates to build it. `Transcryptor::new`,
  `DistributedTranscryptor::new`, the `*Info::new` constructors, `make_*_factor` and
  `make_*session_keys` take no ciphersuite, in Rust or in the bindings: the transcryptor secret is
  already part of the derivation's hash input, so deployments with different secrets derive
  unrelated factors, and the domain and session separate within a deployment.

  There is no mode byte. RFC 9497 separates its OPRF, VOPRF and POPRF variants that way, but
  verifiable transcryption here derives the *same* factors as plain transcryption and adds
  commitments and proofs on top, so a mode would stop a verifiable and a plain transcryptor from
  interoperating on one session. The hashes are separated by the label of each tag
  (`"DeriveFactor-"`, `"HashToGroup-"`, `"HashToScalar-"`, and the proof transcript's own labels).
- `hmac` is an optional dependency, pulled in by `legacy` only.
- `pseudonymize`, `rekey` and `transcrypt` (functions, `Transcryptor` and `DistributedTranscryptor`
  methods, traits, and the batch variants) take a random number generator and, without the
  `elgamal3` feature, the public key the ciphertext is currently encrypted under, exactly like
  `rerandomize`. The factor-only operations are available as `pseudonymize_raw`, `rekey_raw` and
  `transcrypt_raw`; they must not be applied to untrusted input.
- `SessionPublicKeys` is the public half of `SessionKeys` (`SessionKeys::public()`, named to
  mirror the `.public` field on the per-type key pairs); records
  and JSON values are encrypted with and rerandomized under `SessionPublicKeys` instead of
  `SessionKeys`.
- `KeyProvider::get_key` returns the key by value.
- Python: the transcryption functions and methods take an optional trailing `public_key`
  (required without `elgamal3`; `SessionPublicKeys` or `SessionKeys` for records and JSON).
- JavaScript: the transcryption functions and methods take a trailing public key argument without
  `elgamal3` (`PseudonymSessionPublicKey`, `AttributeSessionPublicKey`, or the new
  `SessionPublicKeys`; `SessionKeys.public()`).
- `peppy`: `pseudonym|attribute rekey|pseudonymize|transcrypt` take `--key`, `json transcrypt`
  takes `--keys` (without `elgamal3`).
- The library is generic over the prime-order group (see *Added*). The ristretto255 API is
  unchanged in use, with these exceptions: `ElGamal::to_bytes` returns a `Vec<u8>` and
  `ElGamal::from_bytes(&[u8; N])` is replaced by `from_slice`; `ElGamalEncrypted::to_bytes` and
  `from_bytes` likewise; the `PublicKey`, `SecretKey`, `RekeyFactor`, `BlindedGlobalSecretKey`,
  `SessionKeyShare`, `Encryptable`, `Encrypted` and `Distributed` traits have an associated
  `Group` type (`Padded` requires it to have an `InvertibleEncoding`); the factor types have
  `from_scalar` instead of `From<ScalarNonZero>` in generic
  code (the ristretto255 aliases keep `From`). The tuple constructors `LongPseudonym(..)`,
  `LongAttribute(..)`, `LongEncryptedPseudonym(..)` and `LongEncryptedAttribute(..)` are
  functions with the same names, since type aliases cannot construct tuple structs.

### Added

- The verifiable operations cite their specification: Doesburg, van Gastel and Poll, *Verifiable
  Blind Pseudonymization via Polymorphic Encryption Using Zero-Knowledge Proofs*, WPES '26
  (doi 10.1145/3847192.3847358), is recorded in `CITATION.cff` and the README.

- `encrypt`, `decrypt`, the transcryption operations and their batch variants accept either the
  one key the data needs or a bundle to take it from, so a caller no longer reaches into the
  session for it: `encrypt(&pseudonym, &keys.public(), rng)` and `decrypt(&encrypted, &keys)`
  alongside the existing `&keys.pseudonym.public` and `&keys.pseudonym.secret`. The key type still
  comes from the data, so a bundle only ever yields the matching half and a pseudonym cannot be
  encrypted, decrypted or rekeyed under an attribute key. The mechanism is the existing
  `KeyProvider` trait, now also implemented for `SessionPublicKeys`, `GlobalSecretKeys` and
  reflexively for every key type. The same widening is in the Python bindings; the JavaScript
  bindings keep their typed parameters, as wasm-bindgen cannot discriminate between exported
  types at runtime.
- The group abstraction of RFC 9497, Section 2.1, as `elgamal::arithmetic::Group`: a marker type
  with the scalar and element types, serialization, hashing to the group and to scalars, random
  scalars and elements, and the generator, with `Ristretto255` (`ristretto255-SHA512`) as its
  instance. `Ristretto255::hash_to_group` and `hash_to_scalar` hash with the shared
  `expand_message_xmd` (RFC 9380) of `elgamal::arithmetic::hashing` under SHA-512 and match the
  RFC 9497 test vectors. Optional encodings:
  `InvertibleEncoding` (the lizard encoding, implemented for ristretto255) and `OaepEncoding` (for
  Weierstrass curves, to be implemented).
- Every group-parameterized type and function lives in a `generic` submodule next to its module
  (`data::simple::generic::Pseudonym<G>`, `keys::types::generic::SessionKeys<G>`,
  `transcryptor::types::generic::Transcryptor<G>`, ...); the names at the module level are type
  aliases pinning `Ristretto255`, so ristretto255 code is unchanged. Functions that infer the
  group from their arguments are generic; the ones that generate keys from randomness alone are
  ristretto255 instances, with generic versions in `generic`. Groundwork for the P-256, P-384 and
  brainpoolP320r1 ciphersuites of the coPRF draft; the bindings and the CLI expose ristretto255
  only.

- `tests/vectors.rs`: test vectors for the ristretto255-SHA512 ciphersuite, as Rust
  constants with one value per line. They pin the protocol's derived values byte for byte, so that
  an unintended change to the hashing or the factor derivation fails the suite instead of passing
  silently. They cover `DeriveFactor` for the three labels, `EncryptPseudonym` /
  `TranscryptPseudonym` / `Decrypt` with a fixed `b` and `r`, a three-element batch of pseudonyms
  and of attributes with the applied permutation recorded, and a session key share with its proof.
  Every sampled scalar comes from a ChaCha20 RNG with an explicit seed, so the vectors are
  reproducible. `tests/vectors.rs` recomputes each value and asserts it against its constant,
  naming the label that changed; update them deliberately with
  `cargo test --features batch,verifiable --test vectors -- --ignored --nocapture`, which prints
  the current values in the layout of the constants.
- `elgamal::dleq`: the DLEQ proofs of RFC 9497 Section 2.2 as a second, additive proof encoding.
  A proof is the two scalars `(c, s)` and serializes to 64 bytes; `ComputeComposites` batches one
  proof over every ciphertext transformed with the same scalar. Cross-checked byte for byte
  against the ristretto255-SHA512 VOPRF test vectors of RFC 9497 Appendix A.1.2, for a single
  pair and for a batch of two. The paper's four-element encoding in `elgamal::zkps` is unchanged
  and remains the default; proofs in the two encodings are not interchangeable.
- `elgamal::verifiable::rfc`: the wire layouts of the draft's "Wire Encodings" section for
  the verifiable operations: `RerandomizeMaterial` (128 bytes), `PseudonymBatchHeader` (448),
  `AttributeBatchHeader` (192) and `SessionKeyShareMaterial` (128). Every `from_slice` rejects a
  wrong length, trailing bytes, a non-canonical scalar and the identity element.
- `benches/dleq.rs`: proof size and generate/verify time for both encodings at m = 1, 10 and 100.
- `elgamal::arithmetic::hashing`: `expand_message_xmd` (RFC 9380, with the RFC's SHA-256 and
  SHA-512 test vectors), and the raw-tag `hash_to_group_with_dst` (`hash_to_ristretto255` with
  SHA-512) and `hash_to_scalar_with_dst` (RFC 9497 `HashToScalar`), cross-checked against the
  RFC 9497 ristretto255-SHA512 test vectors.
- `elgamal::arithmetic::hashing::hash_to_group::<G>(x)`: the `hash_to_group` encoding of
  draft-doesburg-cfrg-coprf, with DST `"HashToGroup-" || contextString` derived from
  `G::CIPHERSUITE`. Its docs state the property every encoding must have (no known discrete-log
  relations; encoding `x` as `x * G` is forbidden) and why the ciphersuite matters here: no secret
  enters this hash. The invertible lizard encoding stays on
  `GroupElement::from_lizard`/`to_lizard`, reachable generically through `InvertibleEncoding`.

  The input is passed to `HashToGroup` unchanged rather than hashed first. Pre-hashing adds no
  collision resistance over a secure hash onto the group, diverges from anyone implementing the
  encoding from the obvious primitive, and makes the hash choice load-bearing in two places
  instead of one. An input of 2^16 bytes or more is still reduced with the ciphersuite's hash
  first, which is the one thing a pre-hash does legitimately. **Hashed pseudonyms change.**
- `Group::Hash`, the hash a ciphersuite identifier names, declared beside `Group::CIPHERSUITE` so
  that a group whose identifier says `-SHA256` cannot hash with SHA-512. Code generic over a
  `Group` reaches the ciphersuite's hash through it; the ristretto255 primitives that the RFC 9380
  and RFC 9497 vectors pin keep hashing with SHA-512 by definition.
- `elgamal::arithmetic::Ciphersuite`, with `identifier()`, `context_string()` (the spec's name for
  the value) and `dst()`, reached through `Group::CIPHERSUITE` and built with the `ciphersuite!`
  macro so that the identifier appears once.
- Python: `libpep.elgamal.arithmetic.ciphersuite` (`Ciphersuite`) and
  `libpep.elgamal.arithmetic.hashing` (`expand_message_xmd_sha512`, `hash_to_group`,
  `hash_to_group_with_dst`, `hash_to_scalar_with_dst`). JavaScript: `Ciphersuite`, `hashToGroup`,
  `hashToGroupWithDst`, `hashToScalarWithDst`, `expandMessageXmdSha512`.
- `peppy point hash-to-group <IDENTIFIER>`: the origin pseudonym of an identifier under the
  ciphersuite.
- `peppy` does verifiable transcryption: `factors commitments` prints the commitments of a
  transition, `--prove` on `pseudonym|attribute rekey|pseudonymize|transcrypt` and
  `json transcrypt` adds the proof (JSON) to the output, and `verify-rekey`,
  `verify-pseudonymize` and `json verify-transcrypt` check a proof against the original
  ciphertext and the commitments (exit status 3 if it does not hold). The `build-binary` feature
  therefore enables `serde` and `verifiable`.
- The verifiable operations on single long values in the bindings: Python
  `Transcryptor.verifiable_long_pseudonymize`, `verifiable_long_pseudonym_rekey` and
  `verifiable_long_attribute_rekey` with the `Verifier.verify_long_*` counterparts and the
  `LongPseudonymPseudonymizationProof`, `LongPseudonymRekeyProof` and `LongAttributeRekeyProof`
  classes; JavaScript `verifiableLongPseudonymize`, `verifyLongPseudonymization` and so on.
- The Python stub generator discovers the submodules by walking the module tree instead of a
  hand-kept list, which had left `libpep.verifier`, `libpep.elgamal.verifiable` and
  `libpep.elgamal.zkps` without stubs; the package stubs re-export their submodules, and the
  generator parses what it writes.
- Python: `EncryptionContext.global_` and `PseudonymizationDomain.global_` (the global context
  and domain) replace `global`, a keyword that made them unreachable, and the global secret
  key parameter of the session key functions is `global_key` so it can be passed by keyword.
  The unreachable `PseudonymizationSecret.from` and `EncryptionSecret.from` are gone; the
  constructors do the same.
- `rekey_public_key` on `PseudonymRekeyInfo`, `AttributeRekeyInfo`, `PseudonymizationInfo` and
  `TranscryptionInfo` (the `factors::RekeyPublicKey` trait): the public key a transcrypted
  ciphertext is encrypted under, to pass along a chain of transcryptors. Exposed in the Python and JavaScript bindings; the
  CLI prints it as `key` / `keys`.

### Removed

- `docs/scalar-mult-counts.md` and `docs/scalar-mult-counts-elgamal3.md`. They analysed scalar
  multiplication counts against a module layout several refactors old, and counted the whole flow
  where the paper separates per-message from per-batch cost, so their totals disagreed with it
  from RSK onwards. Table 1 of the WPES '26 paper is the reference for the cost of each operation.
