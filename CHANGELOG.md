# Changelog

## Unreleased (0.14.0)

The crate version is bumped to 0.14.0: the security fixes below change the
signatures of the transcryption operations, which `cargo semver-checks` flags as
a major change against the published 0.13.0.

### Security

- Every transcryption now rerandomizes the ciphertext before applying the reshuffle and rekey
  factors (RRSK/RRK). Previously the high-level `pseudonymize`, `rekey` and `transcrypt` (and the
  batch variants) applied the factors only, so a malicious sender could place a pseudonym directly
  in a malformed ciphertext and obtain the receiver's pseudonym in the clear.
- The batch shuffle uses unbiased index sampling.
- `GroupElement::from_bytes`, `from_slice` and `from_hex` reject the identity element.
- Factor derivation rejects a factor equal to 1 as well as 0 (derived factors are unchanged in the
  non-degenerate case).

### Breaking changes

- Verifiable operations and the verifiable batch types take `SessionPublicKeys` where they
  previously took `SessionKeys`: verification and batch transport need only the public halves.
  This affects `verified_reconstruct_batch`, `verified_reconstruct_transcryption`,
  `verifiable_transcrypt` and the batch constructors, in Rust and in both bindings. In
  JavaScript the `EncryptedBatch` constructors, their `publicKey()` getter and `transcrypt()`
  now use `SessionPublicKeys`; call `SessionKeys.publicKeys()` to obtain one.

- Factor derivation follows `DeriveFactor` of draft-doesburg-cfrg-coprf: `HashToScalar`
  (RFC 9497, ristretto255-SHA512: `expand_message_xmd` with SHA-512, RFC 9380) over the
  length-prefixed secret, the label and the length-prefixed identifier, with domain separation tag
  `"DeriveFactor-" || contextString`, rejecting 0 and 1 with a counter. **Derived factors and
  session keys change**; the previous HMAC-SHA512 derivation is available behind the new
  `hmac-derivation` feature (mutually exclusive with `legacy`). The `legacy` derivation is
  unchanged.
- A protocol `Context` (`protocol::Context`: mode and ciphersuite identifier, context string
  `"coPRFV1-" || I2OSP(mode, 1) || "-" || identifier`) domain-separates the protocol's hashes. It
  is a property of the ciphersuite, not a parameter: `protocol::ciphersuite()` is the context of
  the ciphersuite this crate implements, and factor derivation uses it internally. It is passed
  explicitly only to `encodings::hash_to_group`, the one hash that takes no secret and where the
  `"coPRFV1-"` prefix is what separates a pseudonym from an RFC 9497 OPRF evaluation of the same
  identifier on the same group. `Transcryptor::new`, `DistributedTranscryptor::new`, the
  `*Info::new` constructors, `make_*_factor` and `make_*session_keys` take no context, in Rust or
  in the bindings: the transcryptor secret is already part of the derivation's hash input, so
  deployments with different secrets derive unrelated factors, and the domain and session separate
  within a deployment.
- `hmac` is an optional dependency, pulled in by `legacy` and `hmac-derivation` only.
- `peppy`: `point hash-to-group` takes a `--protocol <IDENTIFIER>` option (default
  `ristretto255-SHA512`), the ciphersuite context its hash is domain-separated with; no other
  command takes one. `--context` remains the encryption context (session) of `keys session` and
  the transcryption commands.
- `pseudonymize`, `rekey` and `transcrypt` (functions, `Transcryptor` and `DistributedTranscryptor`
  methods, traits, and the batch variants) take a random number generator and, without the
  `elgamal3` feature, the public key the ciphertext is currently encrypted under, exactly like
  `rerandomize`. The factor-only operations are available as `pseudonymize_raw`, `rekey_raw` and
  `transcrypt_raw`; they must not be applied to untrusted input.
- `SessionPublicKeys` is the public half of `SessionKeys` (`SessionKeys::public_keys()`); records
  and JSON values are encrypted with and rerandomized under `SessionPublicKeys` instead of
  `SessionKeys`.
- `KeyProvider::get_key` returns the key by value.
- Python: the transcryption functions and methods take an optional trailing `public_key`
  (required without `elgamal3`; `SessionPublicKeys` or `SessionKeys` for records and JSON).
- JavaScript: the transcryption functions and methods take a trailing public key argument without
  `elgamal3` (`PseudonymSessionPublicKey`, `AttributeSessionPublicKey`, or the new
  `SessionPublicKeys`; `SessionKeys.publicKeys()`).
- `peppy`: `pseudonym|attribute rekey|pseudonymize|transcrypt` take `--key`, `json transcrypt`
  takes `--keys` (without `elgamal3`).

### Added

- `elgamal::dleq`: the DLEQ proofs of RFC 9497 Section 2.2 as a second, additive proof encoding.
  A proof is the two scalars `(c, s)` and serializes to 64 bytes; `ComputeComposites` batches one
  proof over every ciphertext transformed with the same scalar. Cross-checked byte for byte
  against the ristretto255-SHA512 VOPRF test vectors of RFC 9497 Appendix A.1.2, for a single
  pair and for a batch of two. The paper's four-element encoding in `elgamal::zkps` is unchanged
  and remains the default; proofs in the two encodings are not interchangeable.
- `elgamal::verifiable::rfc`: the wire layouts of the draft's "Wire Encodings" section for
  modeVcoPRF: `RerandomizeMaterial` (128 bytes), `PseudonymBatchHeader` (448),
  `AttributeBatchHeader` (192) and `SessionKeyShareMaterial` (128). Every `from_slice` rejects a
  wrong length, trailing bytes, a non-canonical scalar and the identity element.
- `benches/dleq.rs`: proof size and generate/verify time for both encodings at m = 1, 10 and 100.
- `elgamal::arithmetic::hashing`: `expand_message_xmd` (RFC 9380, with the RFC's SHA-256 and
  SHA-512 test vectors), `hash_to_group` (`hash_to_ristretto255` with SHA-512) and
  `hash_to_scalar` (RFC 9497 `HashToScalar`), cross-checked against the RFC 9497
  ristretto255-SHA512 test vectors.
- `encodings`: the element encodings of draft-doesburg-cfrg-coprf as plain functions:
  `hash_to_group(x, &Context)` with DST `"HashToGroup-" || contextString`, `encode_lizard` and
  `decode_lizard` (`GroupElement::from_lizard`/`to_lizard` wrap them), and `encode_oaep` and
  `decode_oaep` as stubs until a Weierstrass curve ciphersuite exists. The module documents the
  property every encoding must have (no known discrete-log relations; `x * G` is forbidden).
- `protocol::Context` and `protocol::Mode`, with `Context::context_string()` and `Context::dst()`,
  and `protocol::ciphersuite()`, the context of the ciphersuite this crate implements.
- Python: `libpep.protocol` (`Context`, `Mode`), `libpep.encodings` (`hash_to_group`,
  `encode_lizard`, `decode_lizard`) and `libpep.elgamal.arithmetic.hashing`
  (`expand_message_xmd_sha512`, `hash_to_group`, `hash_to_scalar`). JavaScript: `Context`,
  `Mode`, `encodeLizard`, `decodeLizard`, `hashToGroup`, `hashToGroupWithDst`,
  `hashToScalarWithDst`, `expandMessageXmdSha512`.
- `peppy point hash-to-group <IDENTIFIER>`: the origin pseudonym of an identifier under the
  protocol context.
- `rekey_public_key` on `PseudonymRekeyInfo`, `AttributeRekeyInfo` and `PseudonymizationInfo`, and
  `rekey_public_keys` on `TranscryptionInfo`: the public key a transcrypted ciphertext is encrypted
  under, to pass along a chain of transcryptors. Exposed in the Python and JavaScript bindings; the
  CLI prints it as `key` / `keys`.
