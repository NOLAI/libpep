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

- Factor derivation follows `DeriveFactor` of draft-doesburg-cfrg-coprf: `HashToScalar`
  (RFC 9497, ristretto255-SHA512: `expand_message_xmd` with SHA-512, RFC 9380) over the
  length-prefixed secret, the label and the length-prefixed identifier, with domain separation tag
  `"DeriveFactor-" || contextString`, rejecting 0 and 1 with a counter. **Derived factors and
  session keys change**; the previous HMAC-SHA512 derivation is available behind the new
  `hmac-derivation` feature (mutually exclusive with `legacy`). The `legacy` derivation is
  unchanged.
- A protocol `Context` (`protocol::Context`: mode and ciphersuite identifier, context string
  `"coPRFV1-" || I2OSP(mode, 1) || "-" || identifier`) is a parameter of `Transcryptor::new`,
  `DistributedTranscryptor::new`, the `*Info::new` constructors, `make_*_factor` and
  `make_*session_keys`. `Context::default()` is `ristretto255-SHA512` in `Mode::CoPRF`. Python
  and JavaScript take it as an optional trailing `context` argument (JavaScript accepts a
  `Context` instance or a plain `{mode, identifier}` object).
- `hmac` is an optional dependency, pulled in by `legacy` and `hmac-derivation` only.
- `peppy`: the global `--protocol <IDENTIFIER>` option sets the protocol context (default
  `ristretto255-SHA512`); `--context` remains the encryption context (session) of `keys session`
  and the transcryption commands.
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

- `elgamal::arithmetic::hashing`: `expand_message_xmd` (RFC 9380, with the RFC's SHA-256 and
  SHA-512 test vectors), `hash_to_group` (`hash_to_ristretto255` with SHA-512) and
  `hash_to_scalar` (RFC 9497 `HashToScalar`), cross-checked against the RFC 9497
  ristretto255-SHA512 test vectors.
- `encodings`: the element encodings of draft-doesburg-cfrg-coprf as plain functions:
  `hash_to_group(x, &Context)` with DST `"HashToGroup-" || contextString`, `encode_lizard` and
  `decode_lizard` (`GroupElement::from_lizard`/`to_lizard` wrap them), and `encode_oaep` and
  `decode_oaep` as stubs until a Weierstrass curve ciphersuite exists. The module documents the
  property every encoding must have (no known discrete-log relations; `x * G` is forbidden).
- `protocol::Context` and `protocol::Mode`, with `Context::context_string()` and `Context::dst()`.
- `Transcryptor::context()`.
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
