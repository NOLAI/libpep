# Changelog

## Unreleased (0.14.0)

The crate version is bumped to 0.14.0: the security fixes below change the
signatures of the transcryption operations, which `cargo semver-checks` flags as
a major change against the published 0.13.0.

### API changes

- Every generic type defaults its parameter to ristretto255, so that code which does not need
  another group writes no type parameters: `Pseudonym<G: Group = Ristretto255>` and the other
  types generic over a group (data, keys, factors, proofs, `Client`, ...), and
  `Transcryptor<C: Ciphersuite = Ristretto255Sha512>`, `DistributedTranscryptor`, `Verifier` and the
  master secrets for the types generic over a ciphersuite. `Pseudonym<OtherGroup>` and
  `Transcryptor<OtherSuite>` work as before. Rust does not use a default to infer a type
  parameter, so an expression that nothing constrains (`Pseudonym::random(rng).to_hex()`) still
  needs a type, for example `let p: Pseudonym = ...`.
- The functions and constructors whose group or ciphersuite cannot be inferred from their
  arguments now come in pairs. The plain name is the ristretto255 function, with no type
  parameter: `make_global_keys`, `make_pseudonym_global_keys`, `make_attribute_global_keys`,
  `make_session_keys`, `make_pseudonym_session_keys`, `make_attribute_session_keys`,
  `make_distributed_global_keys` (and its pseudonym and attribute variants),
  `make_pseudonymization_factor`, `make_pseudonym_rekey_factor`, `make_attribute_rekey_factor`,
  `hash_to_group`, `hash_to_nonzero_scalar`, `make_pseudonym_session_key_share_with_proof`,
  `make_attribute_session_key_share_with_proof`, `make_session_key_shares_with_proof`,
  `verifiable_rerandomize` and `verifiable_rerandomize_batch`, and the inherent constructors
  `Transcryptor::new`, `DistributedTranscryptor::new`, `Verifier::new`,
  `Verifier::with_cache_capacity`, `PseudonymizationInfo::new`, `PseudonymRekeyInfo::new`,
  `AttributeRekeyInfo::new`, `TranscryptionInfo::new` and `random` of the master secrets. The
  generic version has the same name with the suffix `_generic` and takes the group or ciphersuite
  as a type parameter: `make_global_keys_generic::<G, _>(rng)`,
  `make_session_keys_generic::<C>(..)`, `Transcryptor::<C>::new_generic(..)`,
  `TranscryptionInfo::new_generic::<C>(..)`. This is a rename of the previous generic functions
  and constructors (`make_global_keys::<G, _>`, `Transcryptor::<C>::new`, `TranscryptionInfo::new::<C>`,
  ...). Methods that take the ciphersuite as a type parameter (`proof.verify::<C>(..)`,
  `verifiable_pseudonymize::<C>`) keep their form.
- `libpep::prelude::*` imports what a typical application needs (the ristretto255 markers, contexts, data types and their traits, keys, secrets, and the client and transcryptor operations); `prelude::client` and `prelude::transcryptor` are the role-specific subsets. After `use libpep::prelude::*;`, `make_global_keys(rng)`, `make_session_keys(..)` and `Transcryptor::new(..)` need no type annotation.
- `PseudonymizationDomain`, `EncryptionContext`, `PseudonymizationSecret` and `EncryptionSecret`
  implement `From` (`&str` and `String`; `&[u8]`, `Vec<u8>` and `Box<[u8]>`) instead of an
  inherent `from`, so `"x".into()` works and the secrets expose `as_bytes`.
- The four factor types implement one `factors::Factor` trait (`from_scalar`, `scalar`); the
  `RekeyFactor` trait is gone. The factor types and the key types keep their scalar or element
  private: there are no public tuple constructors and no `From<ScalarNonZero>` or
  `From<GroupElement>` impls on them, so a value is made with `from_scalar` or `from_point`, or
  derived or generated. The public key a ciphertext is encrypted under after a
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
  preprocessing is `Batchable::preprocess_for_batch`, a trait of `data::batch` that every encryptable type implements.
- Padding and parsing errors are typed: `data::padding::PaddingError` replaces `std::io::Error`
  in the padded encodings and `pad_to`, `data::errors::ParseError` (also reachable as `data::records::ParseError` and `data::long::ParseError`) in the
  string decoders of long encrypted values and records, and `JsonError` wraps a `PaddingError` instead of a string.
  `CacheRegistrationError` and `ZeroArgumentError` are `thiserror` errors. There is no `errors`
  module any more: `BatchError` is `data::batch::BatchError` and exists only with the `batch`
  feature.
- Names: `make_pseudonymisation_factor` is `make_pseudonymization_factor`, and
  `Transcryptor::pseudonymisation_secret` is `pseudonymization_secret`, in Rust and the bindings.
  `PEPJSONValue`, `EncryptedPEPJSONValue`, `PEPJSONBuilder` and `JSONStructure` are
  `PepJsonValue`, `EncryptedPepJsonValue`, `PepJsonBuilder` and `JsonStructure`; the Python and
  JavaScript classes follow. `data::json::utils` (the byte encodings of JSON booleans and numbers)
  is public.
- `Group` is the group arithmetic only; hashing moved to a new `Ciphersuite` trait
  (`elgamal::arithmetic::Ciphersuite`) with a `Group`, a `Hash`, a `CiphersuiteId` and the
  `hash_to_group` and `hash_to_scalar` maps. `Group` lost `Hash`, `CIPHERSUITE`, `hash_to_group`
  and `hash_to_scalar`, and keeps `element_from_uniform_bytes` and `scalar_from_uniform_bytes`.
  The former `Ciphersuite` struct is `CiphersuiteId`, and `Ristretto255Sha512` is the ciphersuite
  of ristretto255 with SHA-512 (its group is `Ristretto255`). Data types, keys, factors and
  proofs stay generic over the group (`Pseudonym<G>`, `Proof<G>`); what hashes is generic over a
  ciphersuite `C`: `hash_to_group::<C>`, `hash_to_nonzero_scalar::<C>`, `make_*_factor::<C>`,
  `make_*session_keys::<C>`, the `*Info::new::<C>` constructors, creating and verifying proofs
  (`create_proof::<C, _>`, `VerifiableRekey::new::<C, _>`, `proof.verify::<C>(..)`, the
  `Verifiable*` traits of the data layer), and the types `Transcryptor<C>`,
  `DistributedTranscryptor<C>`, `Verifier<C>` and the four `Master*` types of
  `verifiable-derivation`. Proof bytes, derived factors and hashed pseudonyms are unchanged. The
  Python and JavaScript bindings are unchanged.
- The verifiable commitments expose their group element through `point()` and are built from
  the transcryption infos with `From` (`VerifiablePseudonymizationCommitment::from(info)` and
  so on).
- The verifiable primitives of `elgamal` (`elgamal::verifiable`, `elgamal::zkps`,
  `elgamal::dleq`) are generic over the group. For this, `Group` gained `ScalarCanBeZero`, the
  scalar field with its addition, and its encoding functions, and `hashing::hash_to_nonzero_scalar`,
  the group's hash reduced to a non-zero scalar. Proof bytes on ristretto255 are unchanged.
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
- Module layout: `elgamal` is the generic low-level API, with the ciphertext in
  `elgamal::ciphertext` (re-exported as `elgamal::ElGamal`, `encrypt` and `decrypt`), and the
  ristretto255 group, its scalars (`ScalarNonZero`, `ScalarCanBeZero`), group elements and raw-tag
  hash functions in `elgamal::arithmetic::ristretto255` (`group_elements` and `scalars` are still
  re-exported from `elgamal::arithmetic`; `hash_to_group_with_dst` and `hash_to_scalar_with_dst`
  are in `elgamal::arithmetic::ristretto255::hashing`, re-exported from `elgamal::arithmetic::hashing`). The high level has no ristretto255 alias
  layer and no `generic` submodules; each module is one file, or a module whose `mod.rs` only
  declares and re-exports. `TranscryptorId` lives in `contexts` (still re-exported from
  `transcryptor`), `Batchable` in `data::batch`, `SessionKeyShareProof::verify_share` in
  `keys::distribution::shares`, and the ElGamal-specific data traits (`ElGamalEncryptable`,
  `ElGamalEncrypted`) in `data::elgamal`, so `data::traits` does not name the scheme.
- The ciphertext is `ElGamal<G>`, and `elgamal::encrypt` and `decrypt` are generic over the group
  (inferred from their arguments). `ElGamal::<G>::LENGTH` replaces the constant `ELGAMAL_LENGTH`;
  it is `2 * G::NE` bytes, or `3 * G::NE` with `elgamal3`.
- Every public item is documented (`missing_docs` warns).
- In the JavaScript bindings, `fromHash` returns `undefined` for input that is not 64 bytes
  instead of aborting.

- The data-layer proof traits provide `verify` as `verified_reconstruct(..).is_some()`, so an
  implementation only supplies `verified_reconstruct`.
- `elgamal::dleq::generate_proof` and `verify_proof` take the ciphersuite from their type
  parameter (`C::ID`) instead of an argument; `generate_proof_with` and `verify_proof_with` keep
  explicit tags. `CiphersuiteId` (the identifier) does not implement serde, and
  `CiphersuiteId::new` is hidden: it exists for the `ciphersuite!` macro.
- `unverified_reconstruct` on the RSK and RRSK proofs and their batches (`insecure`) takes no
  originals, which it never used. `VerifiableRerandomizeBatch::verify` checks the number of
  originals.
- The `verifiable-derivation` methods return typed values: `derive_reshuffle_factor`,
  `derive_pseudonym_rekey_factor` and `derive_attribute_rekey_factor` give the factor types, and
  the `compute_*_commitment` functions the commitment types. In the bindings the methods are
  `derive_pseudonym_rekey_factor` / `derivePseudonymRekeyFactor` and the attribute counterparts.
- In the JavaScript bindings, `verifiablePseudonymize`, `verifiablePseudonymRekey` and
  `verifiableAttributeRekey` return `PseudonymPseudonymizationProof`, `PseudonymRekeyProof` and
  `AttributeRekeyProof` objects (with `toJSON`/`fromJSON`) instead of JSON strings, and the
  `Verifier` methods take them; Python returns and takes the same classes. The module-level
  `verifiable_*` functions of `elgamal.verifiable` that duplicated the classes' constructors are
  gone from both bindings, except `verifiable_rerandomize` and `verifiable_rerandomize_batch`.

### Security

- Session key share verification did not bind the received scalar to the proof.
  `SessionKeyShareProof::verify` checks the ZKP against the blinding and rekey commitments, but
  it never sees the share scalar `u_i`, so a transcryptor could hand over a valid proof alongside
  an unrelated share and nothing would catch it. `verify_share` (and `matches_share`) additionally
  check `U_i == u_i · G`, as the WPES '26 paper requires; `verify` remains for verifiers that hold
  only public values and now documents what it does not establish. Exposed in Python as
  `verify_share` and in JavaScript as `verifyPseudonymShare` / `verifyAttributeShare`.
- The Fiat-Shamir challenge of the Schnorr proofs (`elgamal::zkps`) is domain separated: it is
  the ciphersuite's `HashToScalar` of `A || M || N || c1 || c2` under the tag
  `"ZKPChallenge-" || contextString`, as the DLEQ proofs already were, so a proof of one
  deployment or proof type never verifies as another. Proofs made by earlier versions do not
  verify; the test vectors are regenerated.
- Every block of a long value and every leaf of a JSON document is rerandomized with its own
  factor. One factor shared across a value left the differences between its ciphertexts intact
  through rekeying, which linked a shuffled batch of long attributes or JSON documents to its
  input.
- Every transcryption now rerandomizes the ciphertext before applying the reshuffle and rekey
  factors (RRSK/RRK). Previously the high-level `pseudonymize`, `rekey` and `transcrypt` (and the
  batch variants) applied the factors only, so a malicious sender could place a pseudonym directly
  in a malformed ciphertext and obtain the receiver's pseudonym in the clear.
- The batch shuffle uses unbiased index sampling.
- `GroupElement::from_bytes`, `from_slice` and `from_hex` reject the identity element.
- Factor derivation rejects a factor equal to 1 as well as 0 (derived factors are unchanged in the
  non-degenerate case).

- Secrets are wiped from memory: the byte secrets (`PseudonymizationSecret`, `EncryptionSecret`)
  and the Carter-Wegman master secrets zeroize on drop, and the secret keys, factors, blinding
  factors and shares implement `zeroize::Zeroize` (they are `Copy`, so wiping them is the
  caller's call).

### Breaking changes

- The `build-binary` feature is `cli` and no longer a default feature, so the library no longer
  pulls in clap. Install `peppy` with `cargo install libpep --features cli`.
- The batch slice functions (`pseudonymize_batch`, `rekey_batch`, `transcrypt_batch` and their
  verifiable and transcryptor counterparts) take `&[E]` and no longer shuffle the caller's slice
  in place; the output is shuffled. The test vectors of the batch outputs are regenerated.
- Under `batch-pk`, the batch proofs verify against the key stored in the original batch:
  `verified_reconstruct_batch` (and `Verifier::verify_*_batch`) no longer take the original's key
  as a separate argument, and reject a batch whose stored key is not the one the proof was made
  for. The bindings follow.
- A long pseudonym's pseudonymization proof is one RRSK batch proof over its blocks
  (`LongPseudonymPseudonymizationProof(VerifiableRRSKBatch)`), sharing the factor proofs, instead
  of one proof per block.
- The string form of a `LongEncryptedRecord` prefixes each list with its count
  (`{n}:{items};{m}:{items}`), so a record with no pseudonyms or attributes round-trips;
  `ParseError::InvalidCount` reports a bad count.

- A transcryptor has one blinding factor, used for its pseudonym and attribute shares alike
  (Section 2.2.4 of the paper), so it publishes one `BlindingCommitment`: `BlindingCommitments`
  is gone, `Verifier::register_blinding_commitment`, `blinding_commitment` and
  `has_blinding_commitment` take and return one, and
  `verify_session_key_share_with_commitment` no longer takes a pseudonym/attribute flag.
- A session key share is proved as the paper's Section 3.5 describes, by the transcryptor that
  holds the blinding factor and the rekey factor: `make_session_key_share_with_proof` (with the
  pseudonym, attribute and `shares` variants) returns the share and `ZKP{U_i = b_i · K_i}`, and
  `DistributedTranscryptor::pseudonym_session_key_share_with_proof`,
  `attribute_session_key_share_with_proof` and `session_key_shares_with_proof` do the same for a
  session. `make_pseudonym_session_keys_with_proof`, `make_attribute_session_keys_with_proof` and
  `make_session_key_pair_with_proof`, which needed the global secret key the dealer discards,
  are gone; `SessionKeyShareError` lives in `keys::distribution`. The bindings follow
  (`DistributedTranscryptor.session_key_shares_with_proof` and friends), and
  `peppy keys distributed share --prove` prints the proofs.
- Python `make_pseudonym_rekey_factor`, `make_attribute_rekey_factor` and
  `make_pseudonymization_factor` take an `EncryptionContext` or `PseudonymizationDomain`
  instead of a string, like every other function; JavaScript likewise.
- The bindings gate the session key share proofs and the verifier's blinding-commitment and
  cached-verification methods on `verifiable`, as the library does, instead of
  `verifiable-derivation`.
- `EncryptedBatch` keeps its items and key private, so a batch is only built through `new` or
  deserialization, both of which check that the items share one structure; `public_key()`,
  `as_items()` and `into_items()` read them.
- `PepJsonBuilder::pseudonym` (and `pseudonym(..)` in `pep_json!`) always pads the identifier;
  group elements go in through `pseudonym_hex` (`pseudonym_hex(..)` in the macro) instead of
  being detected from the string.
- Secrets, secret keys, blinding factors, session key shares and factors print redacted through
  `Debug`. `InMemoryCommitmentsCache` no longer derives serde (its tuple keys never serialized
  to JSON). `VerifiableRSKInner::verify` is crate-private. The `LongEncryptable` and
  `LongEncrypted` traits are gone. `PaddingError::CountMismatch` replaces the misused
  `TooManyBlocks` for a record with the wrong number of values. JSON objects are `BTreeMap`s.
- Under `elgamal3` a verifiable batch proof over a batch without pseudonyms (attribute-only
  records, JSON without pseudonym fields, an empty batch) verifies its rekey proofs instead of
  always failing.
- `Verifier::pseudonymization_commitments`, `pseudonym_rekey_commitments` and
  `attribute_rekey_commitments` return registered commitments, so batch proofs can be checked
  against the cache.
- `make_distributed_global_keys` and its pseudonym and attribute variants panic for zero
  transcryptors with a message (they always panicked); the bindings raise an error. The
  derivation inputs (secrets, domains, contexts) must be shorter than
  `factors::derivation::MAX_INPUT_LENGTH`; the CLI and the bindings refuse longer ones instead
  of panicking.
- JavaScript: `encryptJson`, `decryptJson`, `transcryptJson`, `transcryptJsonBatch`,
  `encryptJsonBatch`, `decryptJsonBatch` and `verifyJsonTranscryption` are the only spellings;
  the `JSON` duplicates are gone. `OfflinePEPClient` is `OfflineClient`, `rekeyPublicKeys` is
  `rekeyPublicKey`. Python: a batch function given items of different types raises `TypeError`
  instead of panicking.
- `peppy`: `--encryption-secret` and `--pseudonymization-secret` name the secrets everywhere
  (`--secret` is gone from `factors reshuffle|rekey`, `keys session derive` and
  `keys distributed share`); `attribute transcrypt` no longer accepts the pseudonymization
  flags; `encode`/`decode` use the PKCS#7 padding of the library, so an identifier gives the
  same pseudonym on the command line as in a JSON document or the bindings; values print bare
  when standard output is piped and labelled on a terminal; a wrong-key decryption exits with
  3 and a failed proof with 4, since clap uses 2; `keys distributed reconstruct` refuses a call
  without shares or with shares of a kind whose blinded key is missing.

- The minimum supported Rust version is 1.88, up from 1.85. Transitive dependencies of
  `curve25519-dalek`, `sha2` and `hmac` raised their own floors during this cycle: `ctutils`
  0.4.3 requires 1.87 and `sha2` 0.11.1 requires 1.88.
- Verifiable operations and the verifiable batch types take `SessionPublicKeys` where they
  previously took `SessionKeys`: verification and batch transport need only the public halves.
  This affects `verified_reconstruct_batch`, `verified_reconstruct_transcryption`,
  `verifiable_transcrypt` and the batch constructors, in Rust and in both bindings. In
  JavaScript the `EncryptedBatch` constructors, their `publicKey()` getter and `transcrypt()`
  now use `SessionPublicKeys`; call `SessionKeys.public()` to obtain one.

- Factor derivation is `DeriveFactor`: `HashToScalar`
  (ristretto255-SHA512: `expand_message_xmd` with SHA-512, RFC 9380) over the
  length-prefixed secret, the label and the length-prefixed identifier, with domain separation tag
  `"DeriveFactor-" || contextString`, rejecting 0 and 1 with a counter. **Derived factors and
  session keys change**, and the HMAC-SHA512 derivation of 0.13 is gone: `DeriveFactor` is the
  only derivation outside `legacy`, which is unchanged and still reproduces the PEP repository
  implementation bit for bit.
- A `Ciphersuite` (`elgamal::arithmetic::Ciphersuite`, a trait) pairs a `Group` with the hash its
  protocol hashes with, and names itself with a `CiphersuiteId` (the identifier, context string
  `"nPEPV1-" || identifier`) that domain-separates the protocol's hashes. An identifier names a
  group and a hash together (`ristretto255-SHA512`), so it is the associated constant `Ciphersuite::ID`
  of one implementation and cannot be constructed from an arbitrary string. The identifier is
  `Copy` and const-constructible, and its context string is a `&'static [u8]`, so neither factor
  derivation nor hashing allocates to build it. The bindings take no ciphersuite argument: the
  transcryptor secret is already part of the derivation's hash input, so deployments with
  different secrets derive unrelated factors, and the domain and session separate within a
  deployment.

  There is no mode byte: verifiable transcryption here derives the *same* factors as plain transcryption and adds
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
- The whole API is generic over the prime-order group and, where it hashes, over the ciphersuite
  (see *Added*): the `elgamal` module and the high-level API (`data`, `keys`, `factors`, `client`,
  `transcryptor`, `verifier`) take a `G: Group` parameter (`elgamal::arithmetic::Group`) or a
  `C: Ciphersuite` parameter, which users instantiate with `Ristretto255`
  (`Pseudonym<Ristretto255>`) or `Ristretto255Sha512` (`Transcryptor<Ristretto255Sha512>`). The
  group is inferred wherever it follows from the arguments; functions that create keys from
  randomness alone take it explicitly (`make_global_keys::<Ristretto255, _>`). The bindings,
  `peppy` and the tests name the group and the ciphersuite once in a small aliases file. Other changes: `ElGamal<G>` is generic; `ElGamal::to_bytes` returns a
  `Vec<u8>` and `ElGamal::from_bytes(&[u8; N])` is replaced by `from_slice`; `ElGamalEncrypted::to_bytes`
  and `from_bytes` likewise; `elgamal::zkps` and `elgamal::dleq` are generic over the group;
  `BatchError` is `data::batch::BatchError` and exists only with the `batch` feature, and
  `ParseError` is `data::errors::ParseError`. The error variants that only the `long` feature
  can produce exist only with it.

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
- The group abstraction `elgamal::arithmetic::Group`: a marker type
  with the scalar and element types, serialization, the maps from uniform bytes to scalars and
  elements, random scalars and elements, and the generator, with `Ristretto255` as its instance.
  `Ristretto255Sha512::hash_to_group` and `hash_to_scalar` hash with the shared
  `expand_message_xmd` (RFC 9380) of `elgamal::arithmetic::hashing` under SHA-512 and match the
  published ristretto255-SHA512 test vectors. Optional encodings:
  `InvertibleEncoding` (the lizard encoding, implemented for ristretto255) and `OaepEncoding` (for
  Weierstrass curves, to be implemented).
- The whole API (`elgamal`, `data`, `keys`, `factors`, `client`, `transcryptor`, `verifier`) is
  generic over the group and the ciphersuite, so other groups and hashes can be built on it. The
  bindings and the CLI use ristretto255 with SHA-512.

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
- `elgamal::dleq`: DLEQ proofs, generic over the group, as a second, additive proof encoding.
  A proof is the two scalars `(c, s)` and serializes to 64 bytes; `ComputeComposites` batches one
  proof over every ciphertext transformed with the same scalar. Cross-checked byte for byte
  against the published ristretto255-SHA512 VOPRF test vectors, for a single
  pair and for a batch of two. The paper's four-element encoding in `elgamal::zkps` is unchanged
  and remains the default; proofs in the two encodings are not interchangeable.
- `benches/dleq.rs`: proof size and generate/verify time for both encodings at m = 1, 10 and 100.
- `elgamal::arithmetic::hashing`: `expand_message_xmd` (RFC 9380, with the RFC's SHA-256 and
  SHA-512 test vectors), and in `elgamal::arithmetic::ristretto255::hashing` (re-exported here) the raw-tag
  `hash_to_group_with_dst` (`hash_to_ristretto255` with SHA-512) and `hash_to_scalar_with_dst`
  (`HashToScalar`), cross-checked against the published ristretto255-SHA512 test vectors.
- `elgamal::arithmetic::hashing::hash_to_group::<C>(x)`: the `hash_to_group` encoding of
  an identifier, with DST `"HashToGroup-" || contextString` derived from
  `C::ID`, where `C` is the `Ciphersuite`. Its docs state the property every encoding must have (no known discrete-log
  relations; encoding `x` as `x * G` is forbidden) and why the ciphersuite matters here: no secret
  enters this hash. The invertible lizard encoding stays on
  `GroupElement::from_lizard`/`to_lizard`, reachable generically through `InvertibleEncoding`.

  The input is passed to `HashToGroup` unchanged rather than hashed first. Pre-hashing adds no
  collision resistance over a secure hash onto the group, diverges from anyone implementing the
  encoding from the obvious primitive, and makes the hash choice load-bearing in two places
  instead of one. An input of 2^16 bytes or more is still reduced with the ciphersuite's hash
  first, which is the one thing a pre-hash does legitimately. **Hashed pseudonyms change.**
- `Ciphersuite::Hash`, the hash a ciphersuite identifier names, declared beside `Ciphersuite::ID`
  so that a ciphersuite whose identifier says `-SHA256` cannot hash with SHA-512. Code generic
  over a `Ciphersuite` reaches its hash through it; the ristretto255 primitives that the RFC 9380
  and published test vectors pin keep hashing with SHA-512 by definition.
- `elgamal::arithmetic::CiphersuiteId`, with `identifier()`, `context_string()` and `dst()`,
  reached through `Ciphersuite::ID` and built with the `ciphersuite!` macro so that the
  identifier appears once.
- Python: `libpep.elgamal.arithmetic.ciphersuite` (`Ciphersuite`) and
  `libpep.elgamal.arithmetic.hashing` (`expand_message_xmd_sha512`, `hash_to_group`,
  `hash_to_group_with_dst`, `hash_to_scalar_with_dst`). JavaScript: `Ciphersuite`, `hashToGroup`,
  `hashToGroupWithDst`, `hashToScalarWithDst`, `expandMessageXmdSha512`.
- `peppy point hash-to-group <IDENTIFIER>`: the origin pseudonym of an identifier under the
  ciphersuite.
- The `verifiable-derivation` feature is documented as the alternative of Section 3.3.1 of the
  paper and not the preferred scheme: its factors are linear in two public hashes, so two leaked
  factors, two pseudonyms of one subject or two session keys reveal all of them.
- `peppy` does verifiable transcryption: `factors commitments` prints the commitments of a
  transition, `--prove` on `pseudonym|attribute rekey|pseudonymize|transcrypt` and
  `json transcrypt` adds the proof (JSON) to the output, and `verify-rekey`,
  `verify-pseudonymize` and `json verify-transcrypt` check a proof against the original
  ciphertext and the commitments (exit status 4 if it does not hold).
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

- The `default+verifiable` CI rows (`verifiable` is a default feature); the MSRV job checks the
  default mode and `verifiable-derivation` as well; `cargo doc` runs with warnings denied; docs.rs
  documents the default ciphertext mode with every feature instead of `elgamal3`.

- `docs/scalar-mult-counts.md` and `docs/scalar-mult-counts-elgamal3.md`. They analysed scalar
  multiplication counts against a module layout several refactors old, and counted the whole flow
  where the paper separates per-message from per-batch cost, so their totals disagreed with it
  from RSK onwards. Table 1 of the WPES '26 paper is the reference for the cost of each operation.
