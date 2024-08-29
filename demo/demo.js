import * as libpep from "../pkg-web/libpep.js";

async function wasmInit() {
    await libpep.default();

    let secretKey = libpep.ScalarNonZero.fromHex("044214715d782745a36ededee498b31d882f5e6239db9f9443f6bfef04944906");
    // let publicKey = libpep.GroupElement.G().mul(secretKey);
    let publicKey = libpep.GroupElement.fromBase64("SmQoQ9acvOH-zyJ68zeBOp4FibbQTbcrqETFLEw7DwM=");

    document.getElementById('pseudonym').value = libpep.GroupElement.random().toHex();

    document.getElementById('encrypt').addEventListener('click', function() {
        const input = document.getElementById('pseudonym').value;
        let pseudonym = libpep.GroupElement.fromHex(input);
        if (!pseudonym) alert("Invalid pseudonym");
        let ciphertext = libpep.encrypt(pseudonym, publicKey);

        const output = document.getElementById('encrypted_pseudonym');
        output.value = ciphertext.toBase64();
    });

    document.getElementById('rerandomize').addEventListener('click', function() {
        const input = document.getElementById('encrypted_pseudonym').value;
        let ciphertext = libpep.ElGamal.fromBase64(input);
        if (!ciphertext) alert("Invalid ciphertext");
        let r = libpep.ScalarNonZero.random();
        let rerandomized = libpep.rerandomize(ciphertext, r);
        const output = document.getElementById('encrypted_pseudonym');
        output.value = rerandomized.toBase64();
    });

    document.getElementById('pseudonymize').addEventListener('click', function() {
        const input = document.getElementById('encrypted_pseudonym').value;
        let ciphertext = libpep.ElGamal.fromBase64(input);
        if (!ciphertext) alert("Invalid ciphertext");
        const userFrom = document.getElementById('user_from').value;
        const userTo = document.getElementById('user_to').value;
        let sFrom = libpep.ScalarNonZero.fromHex(userFrom);
        if (!sFrom) alert("Invalid user from");
        let sTo = libpep.ScalarNonZero.fromHex(userTo);
        if (!sTo) alert("Invalid user to");
        let pseudonym = libpep.reshuffleFromTo(ciphertext, sFrom, sTo);
        const output = document.getElementById('new_encrypted_pseudonym');
        output.value = pseudonym.toBase64();
    });

    document.getElementById('decrypt').addEventListener('click', function() {
        const input = document.getElementById('new_encrypted_pseudonym').value;
        let ciphertext = libpep.ElGamal.fromBase64(input);
        if (!ciphertext) alert("Invalid ciphertext");
        let plaintext = libpep.decrypt(ciphertext, secretKey);
        const output = document.getElementById('new_pseudonym');
        output.value = plaintext.toHex();
    });

    document.getElementById('reverse').addEventListener('click', function() {
        document.getElementById('pseudonym').value = document.getElementById('new_pseudonym').value;
        const userTo = document.getElementById('user_to').value;
        document.getElementById('user_to').value = document.getElementById('user_from').value;
        document.getElementById('user_from').value = userTo;
        document.getElementById('encrypt').click();
        document.getElementById('pseudonymize').click();
        document.getElementById('decrypt').click();
    });
}
wasmInit();
