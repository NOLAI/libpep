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
        const inputPseudo = document.getElementById('pseudonym').value;
        const inputData = document.getElementById('data_point').value;

        let inputBytesPseudo = new TextEncoder().encode(inputPseudo);
        let pseudonym;
        if (inputPseudo.length === 64) {
            pseudonym = libpep.Pseudonym.fromHex(inputPseudo);
        } else if (inputBytesPseudo.length === 16) {
            pseudonym = libpep.Pseudonym.fromBytes(inputBytesPseudo);
        } else if (inputBytesPseudo.length < 16) {
            let paddingNeededPseudo = 16 - (inputBytesPseudo.length % 16);
            let paddedBytesPseudo = new Uint8Array(inputBytesPseudo.length + paddingNeededPseudo);
            paddedBytesPseudo.set(inputBytesPseudo);
            pseudonym = libpep.Pseudonym.fromBytes(paddedBytesPseudo);
        }  else {
            alert("Invalid pseudonym (too long)");
        }
        let ciphertextPseudo = libpep.encryptPseudonym(pseudonym, publicKey);

        let inputBytesData = new TextEncoder().encode(inputData);
        let dataPoint;
        if (inputBytesData.length === 16) {
            dataPoint = libpep.DataPoint.fromBytes(inputBytesData);
        } else if (inputBytesData.length < 16) {
            let paddingNeededData = 16 - (inputBytesData.length % 16);
            let paddedBytesData = new Uint8Array(inputBytesData.length + paddingNeededData);
            paddedBytesData.set(inputBytesData);
            dataPoint = libpep.DataPoint.fromBytes(paddedBytesData);
        } else {
            alert("Invalid data point (too long)");
        }
        let ciphertextData = libpep.encryptData(dataPoint, publicKey);

        const outputPseudo = document.getElementById('encrypted_pseudonym');
        const outputData = document.getElementById('encrypted_data_point');
        outputPseudo.value = ciphertextPseudo.asBase64();
        outputData.value = ciphertextData.asBase64();
    });

    document.getElementById('rerandomize').addEventListener('click', function() {
        const inputPseudo = document.getElementById('encrypted_pseudonym').value;
        const inputData = document.getElementById('encrypted_data_point').value;
        let ciphertextPseudo = libpep.EncryptedPseudonym.fromBase64(inputPseudo);
        let ciphertextData = libpep.EncryptedDataPoint.fromBase64(inputData);
        if (!ciphertextPseudo) alert("Invalid pseudonym ciphertext");
        if (!ciphertextData) alert("Invalid data ciphertext");

        let rerandomizedPseudo = libpep.rerandomizePseudonym(ciphertextPseudo, publicKey);
        const outputPseudo = document.getElementById('encrypted_pseudonym');
        outputPseudo.value = rerandomizedPseudo.asBase64();

        let rerandomizedData = libpep.rerandomizeData(ciphertextData, publicKey);
        const outputData = document.getElementById('encrypted_data_point');
        outputData.value = rerandomizedData.asBase64();
    });

    document.getElementById('transcrypt').addEventListener('click', function() {
        const inputPseudo = document.getElementById('encrypted_pseudonym').value;
        let ciphertextPseudo = libpep.EncryptedPseudonym.fromBase64(inputPseudo);
        if (!ciphertextPseudo) alert("Invalid pseudonym ciphertext");

        const inputData = document.getElementById('encrypted_data_point').value;
        let ciphertextData = libpep.EncryptedDataPoint.fromBase64(inputData);
        if (!ciphertextData) alert("Invalid data ciphertext");

        const userFrom = document.getElementById('context_from').value;
        const userTo = document.getElementById('context_to').value;
        let pseudoInfo = new libpep.PseudonymizationInfo(userFrom, userTo, encContext, encContext, pseudoSecret, encSecret);
        let rekeyInfo = new libpep.RekeyInfo(encContext, encContext, encSecret);

        let pseudonym = libpep.pseudonymize(ciphertextPseudo, pseudoInfo);
        const outputPseudo = document.getElementById('new_encrypted_pseudonym');
        outputPseudo.value = pseudonym.asBase64();

        let dataPoint = libpep.rekeyData(ciphertextData, rekeyInfo);
        const outputData = document.getElementById('new_encrypted_data_point');
        outputData.value = dataPoint.asBase64();
    });

    document.getElementById('decrypt').addEventListener('click', function() {
        const inputPseudo = document.getElementById('new_encrypted_pseudonym').value;
        let ciphertextPseudo = libpep.EncryptedPseudonym.fromBase64(inputPseudo);
        if (!ciphertextPseudo) alert("Invalid ciphertext");
        let plaintext = libpep.decryptPseudonym(ciphertextPseudo, secretKey);
        const outputPseudo = document.getElementById('new_pseudonym');
        if (plaintext.asBytes()) {
            outputPseudo.value = new TextDecoder().decode(plaintext.asBytes());
        } else {
            outputPseudo.value = plaintext.asHex();
        }

        const inputData = document.getElementById('new_encrypted_data_point').value;
        let ciphertextData = libpep.EncryptedDataPoint.fromBase64(inputData);
        if (!ciphertextData) alert("Invalid data ciphertext");
        let dataPoint = libpep.decryptData(ciphertextData, secretKey);
        const outputData = document.getElementById('new_data_point');
        outputData.value = new TextDecoder().decode(dataPoint.asBytes());
    });

    document.getElementById('reverse').addEventListener('click', function() {
        document.getElementById('pseudonym').value = null;
        document.getElementById('data_point').value = null;
        document.getElementById('pseudonym').value = String(document.getElementById('new_pseudonym').value);
        document.getElementById('data_point').value = String(document.getElementById('new_data_point').value);
        const userTo = document.getElementById('context_to').value;
        document.getElementById('context_to').value = document.getElementById('context_from').value;
        document.getElementById('context_from').value = userTo;
        document.getElementById('encrypted_pseudonym').value = null;
        document.getElementById('encrypted_data_point').value = null;
        document.getElementById('encrypt').click();
        document.getElementById('transcrypt').click();
        document.getElementById('decrypt').click();
    });
}
wasmInit();
