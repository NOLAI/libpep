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

### Added

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
- `rekey_public_key` on `PseudonymRekeyInfo`, `AttributeRekeyInfo` and `PseudonymizationInfo`, and
  `rekey_public_keys` on `TranscryptionInfo`: the public key a transcrypted ciphertext is encrypted
  under, to pass along a chain of transcryptors. Exposed in the Python and JavaScript bindings; the
  CLI prints it as `key` / `keys`.
