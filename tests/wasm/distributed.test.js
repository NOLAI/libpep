const {
    Attribute,
    GroupElement,
    makeDistributedGlobalKeys,
    DistributedTranscryptor,
    Client,
    Pseudonym,
    PseudonymizationDomain,
    EncryptionContext,
} = require("../../pkg/libpep.js");

// TODO: The n-pep chain-of-transcryptors test needs the recipient public key
// to be tracked per step in non-elgamal3 mode. The WASM `Client` doesn't yet
// expose the session keys directly to JS, so this test is skipped until that
// helper lands. The equivalent Rust integration test in `tests/distributed.rs`
// exercises this path in both modes.
test.skip('n_pep', async () => {});