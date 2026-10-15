# peppy

`peppy` is the command-line interface to [libpep](https://github.com/NOLAI/libpep), a library for polymorphic encryption and pseudonymization.
Install it with `cargo install peppy`.

## Usage

The first word of a command names what is operated on, the second the operation:

| Group | Operations |
|-------|------------|
| `keys global`, `keys session`, `keys distributed` | `generate`; `derive`; `setup`, `share`, `reconstruct`, `update` |
| `factors` | `reshuffle`, `rekey`, `info`, `commitments` |
| `pseudonym`, `attribute` | `random`, `encode`, `decode`, `encrypt`, `decrypt`, `rerandomize`, `rekey`, `transcrypt`, `verify-rekey`, and `pseudonymize`, `verify-pseudonymize` for pseudonyms |
| `json` | `encrypt`, `decrypt`, `transcrypt`, `verify-transcrypt` |
| `elgamal` | `encrypt`, `decrypt`, `rr`, `rs`, `rk`, `rsk`, `rrsk`, `rs2`, `rk2`, `rsk2`, `rrsk2` |
| `scalar`, `point` | `random`, `invert`, `mul`, `from-hash`; `random`, `base`, `mul`, `from-hash`, `hash-to-group` |

`point hash-to-group` domain-separates its hash with the ciphersuite this build implements (`ristretto255-SHA512`); there is one, so there is nothing to select. Factor derivation is separated by the transcryptor secrets, the domain and the session.

Values print one per line on standard output, labelled when that is a terminal and bare when piped; `--json` prints all values of a command as one object, which is the form to use when a command prints several values.
Any value argument may be `-` to read standard input or `@path` to read a file.
Scalars and group elements are hex, ciphertexts base64, and long values are given as space-separated (plain) or `|`-separated (encrypted) blocks.
Malformed input exits with status 1 (a usage error with 2, from clap); with the `elgamal3` feature a decryption with the wrong key exits with status 3; a proof that does not verify exits with status 4.

The [quick start](https://github.com/NOLAI/libpep#quick-start) of libpep, on the command line:

```bash
peppy keys global generate --json > global.json
peppy keys session derive --pseudonym-global-secret "$(jq -r .pseudonym_secret_key global.json)" \
    --encryption-secret "encryption secret" --context session-a --json > session-a.json
peppy keys session derive --pseudonym-global-secret "$(jq -r .pseudonym_secret_key global.json)" \
    --encryption-secret "encryption secret" --context session-b --json > session-b.json

value=$(peppy pseudonym encode patient-42)
encrypted=$(peppy pseudonym encrypt --key "$(jq -r .pseudonym_public_key session-a.json)" "$value")
transcrypted=$(peppy pseudonym transcrypt \
    --pseudonymization-secret "pseudonymization secret" --encryption-secret "encryption secret" \
    --from-domain hospital --to-domain research --from-context session-a --to-context session-b \
    --key "$(jq -r .pseudonym_public_key session-a.json)" "$encrypted" --json | jq -r .ciphertext)
peppy pseudonym decrypt --key "$(jq -r .pseudonym_secret_key session-b.json)" "$transcrypted"
```

## Verifiable transcryption

Transcryption is verifiable on the command line as well: `factors commitments` prints the commitments a transcryptor publishes for a transition, `--prove` on `rekey`, `pseudonymize` and `transcrypt` adds a `proof` (JSON) to the output, and `verify-rekey`, `verify-pseudonymize` and `json verify-transcrypt` check a proof against the original ciphertext and the commitments, printing the transcrypted ciphertext only if it holds.
A proof of `pseudonym transcrypt` is a pseudonymization proof, a proof of `attribute transcrypt` a rekey proof.

```bash
peppy factors commitments \
    --pseudonymization-secret "pseudonymization secret" --encryption-secret "encryption secret" \
    --from-domain hospital --to-domain research --from-context session-a --to-context session-b \
    --json > commitments.json
peppy pseudonym transcrypt --prove \
    --pseudonymization-secret "pseudonymization secret" --encryption-secret "encryption secret" \
    --from-domain hospital --to-domain research --from-context session-a --to-context session-b \
    --key "$(jq -r .pseudonym_public_key session-a.json)" "$encrypted" --json > transcrypted.json
jq -c .proof transcrypted.json > proof.json
peppy pseudonym verify-pseudonymize \
    --reshuffle-commitment "$(jq -r .reshuffle_commitment commitments.json)" \
    --rekey-commitment "$(jq -r .pseudonym_rekey_commitment commitments.json)" \
    --key "$(jq -r .pseudonym_public_key session-a.json)" --proof @proof.json "$encrypted"
```

## Distributed keys

`peppy keys distributed setup -n 3` sets up a system with three transcryptors; each one then answers a client with `keys distributed share`, and the client combines the shares with `keys distributed reconstruct`.
`peppy completions <shell>` prints a completion script and `peppy man` the man page.

## Features

- `json` (default): the `json` commands.
- `elgamal3`: build against libpep's ElGamal triple encryption, in which every ciphertext carries its public key.
- `insecure`: commands that typically should not be used in production.
