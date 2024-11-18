import * as libpep from "../pkg-web/libpep.js";

async function wasmInit() {
    await libpep.default();

    let globalKeys = libpep.makeGlobalKeys();
    let pseudoSecret = new libpep.PseudonymizationSecret(new TextEncoder().encode("pseudoSecret"));
    let encSecret = new libpep.EncryptionSecret(new TextEncoder().encode("encSecret"));
    let encContext = "context";
    let sessionKeys = libpep.makeSessionKeys(globalKeys.secret, encContext, encSecret);
    let secretKey = sessionKeys.secret;
    let publicKey = sessionKeys.public;

    document.getElementById('encrypt').addEventListener('click', function() {
        const input = document.getElementById('pseudonym').value;
        let inputBytes = new TextEncoder().encode(input);
        let pseudonym;
        if (input.length === 64) {
            pseudonym = libpep.Pseudonym.fromHex(input);
        } else if (inputBytes.length === 16) {
            pseudonym = libpep.Pseudonym.fromBytes(inputBytes);
        } else if (inputBytes.length < 16) {
            let paddingNeeded = 16 - (inputBytes.length % 16);
            let paddedBytes = new Uint8Array(inputBytes.length + paddingNeeded);
            paddedBytes.set(inputBytes);
            pseudonym = libpep.Pseudonym.fromBytes(paddedBytes);
        }  else {
            alert("Invalid pseudonym");
        }
        let ciphertext = libpep.encryptPseudonym(pseudonym, publicKey);

        const output = document.getElementById('encrypted_pseudonym');
        output.value = ciphertext.toBase64();
    });

    document.getElementById('rerandomize').addEventListener('click', function() {
        const input = document.getElementById('encrypted_pseudonym').value;
        let ciphertext = libpep.EncryptedPseudonym.fromBase64(input);
        if (!ciphertext) alert("Invalid ciphertext");
        let rerandomized = libpep.rerandomizePseudonym(ciphertext, publicKey);
        const output = document.getElementById('encrypted_pseudonym');
        output.value = rerandomized.toBase64();
    });

    document.getElementById('pseudonymize').addEventListener('click', function() {
        const input = document.getElementById('encrypted_pseudonym').value;
        let ciphertext = libpep.EncryptedPseudonym.fromBase64(input);
        if (!ciphertext) alert("Invalid ciphertext");
        const userFrom = document.getElementById('context_from').value;
        const userTo = document.getElementById('context_to').value;
        let info = new libpep.PseudonymizationInfo(userFrom, userTo, encContext, encContext, pseudoSecret, encSecret);
        let pseudonym = libpep.pseudonymize(ciphertext, info);
        const output = document.getElementById('new_encrypted_pseudonym');
        output.value = pseudonym.toBase64();
    });

    document.getElementById('decrypt').addEventListener('click', function() {
        const input = document.getElementById('new_encrypted_pseudonym').value;
        let ciphertext = libpep.EncryptedPseudonym.fromBase64(input);
        if (!ciphertext) alert("Invalid ciphertext");
        let plaintext = libpep.decryptPseudonym(ciphertext, secretKey);
        const output = document.getElementById('new_pseudonym');
        if (plaintext.toBytes()) {
            output.value = new TextDecoder().decode(plaintext.toBytes());
        } else {
            output.value = plaintext.toHex();
        }
    });

    document.getElementById('reverse').addEventListener('click', function() {
        document.getElementById('pseudonym').value = document.getElementById('new_pseudonym').value;
        const userTo = document.getElementById('context_to').value;
        document.getElementById('context_to').value = document.getElementById('context_from').value;
        document.getElementById('context_from').value = userTo;
        document.getElementById('encrypt').click();
        document.getElementById('pseudonymize').click();
        document.getElementById('decrypt').click();
    });
}
wasmInit();
