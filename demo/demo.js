import * as libpep from "../pkg-web/libpep.js";

async function wasmInit() {
    await libpep.default();

    let globalKeys = libpep.makeGlobalKeys();
    let pseudoSecret = new libpep.PseudonymizationSecret(new Uint8Array(32));
    let encSecret = new libpep.EncryptionSecret(new Uint8Array(32));
    let encContext = "context";
    let sessionKeys = libpep.makeSessionKeys(globalKeys.secret, encContext, encSecret);
    let secretKey = sessionKeys.secret;
    let publicKey = sessionKeys.public;

    document.getElementById('pseudonym').value = libpep.Pseudonym.random().toHex();

    document.getElementById('encrypt').addEventListener('click', function() {
        const input = document.getElementById('pseudonym').value;
        let pseudonym = libpep.Pseudonym.fromHex(input);
        if (!pseudonym) alert("Invalid pseudonym");
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
        output.value = plaintext.toHex();
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
