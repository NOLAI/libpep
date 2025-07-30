const {
    DataPoint, decryptData, decryptPseudonym, encryptData,
    encryptPseudonym,
    GroupElement,
    makeGlobalKeys,
    makeSessionKeys,
    pseudonymize, rekeyData, Pseudonym, PseudonymizationInfo, RekeyInfo, PseudonymizationSecret, EncryptionSecret,
    transcryptBatch, EncryptedEntityData, GlobalPublicKey, EncryptedPseudonym, EncryptedDataPoint
} = require("../../pkg/libpep.js");

test('test high level', async () => {
    const globalKeys = makeGlobalKeys();
    const globalPublicKey = globalKeys.public;
    const globalPrivateKey = globalKeys.secret;

    const secret = Uint8Array.from(Buffer.from("secret"))

    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const domain1 = "domain1";
    const session1 = "session1";
    const domain2 = "domain2";
    const session2 = "session2";

    const session1Keys = makeSessionKeys(globalPrivateKey, session1, encSecret);
    const session2Keys = makeSessionKeys(globalPrivateKey, session2, encSecret);

    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, session1Keys.public);

    const random = GroupElement.random();
    const data = new DataPoint(random);
    const encData = encryptData(data, session1Keys.public);

    const decPseudo = decryptPseudonym(encPseudo, session1Keys.secret);
    const decData = decryptData(encData, session1Keys.secret);

    expect(pseudo.asHex()).toEqual(decPseudo.asHex());
    expect(data.asHex()).toEqual(decData.asHex());

    const pseudoInfo = new PseudonymizationInfo(domain1, domain2, session1, session2, pseudoSecret, encSecret);
    const rekeyInfo = new RekeyInfo(session1, session2, encSecret);

    const rekeyed = rekeyData(encData, rekeyInfo);
    const rekeyedDec = decryptData(rekeyed, session2Keys.secret);

    expect(data.asHex()).toEqual(rekeyedDec.asHex());

    const pseudonymized = pseudonymize(encPseudo, pseudoInfo);
    const pseudonymizedDec = decryptPseudonym(pseudonymized, session2Keys.secret);

    expect(pseudo.asHex()).not.toEqual(pseudonymizedDec.asHex());

    const revPseudonymized = pseudonymize(pseudonymized, pseudoInfo.rev());
    const revPseudonymizedDec = decryptPseudonym(revPseudonymized, session1Keys.secret);

    expect(pseudo.asHex()).toEqual(revPseudonymizedDec.asHex());
})

test('test pseudonym operations', async () => {
    // Test random pseudonym
    const pseudo1 = Pseudonym.random();
    const pseudo2 = Pseudonym.random();
    expect(pseudo1.asHex()).not.toEqual(pseudo2.asHex());
    
    // Test encoding/decoding
    const encoded = pseudo1.encode();
    const decoded = Pseudonym.decode(encoded);
    expect(decoded).not.toBeNull();
    expect(pseudo1.asHex()).toEqual(decoded.asHex());
    
    // Test hex encoding/decoding
    const hexStr = pseudo1.asHex();
    const decodedHex = Pseudonym.fromHex(hexStr);
    expect(decodedHex).not.toBeNull();
    expect(pseudo1.asHex()).toEqual(decodedHex.asHex());
});

test('test data point operations', async () => {
    // Test random data point
    const data1 = DataPoint.random();
    const data2 = DataPoint.random();
    expect(data1.asHex()).not.toEqual(data2.asHex());
    
    // Test encoding/decoding
    const encoded = data1.encode();
    const decoded = DataPoint.decode(encoded);
    expect(decoded).not.toBeNull();
    expect(data1.asHex()).toEqual(decoded.asHex());
});

test('test string padding operations', async () => {
    const testString = "Hello, World! This is a test string for padding.";
    
    // Test pseudonym string padding
    const pseudoList = Pseudonym.fromStringPadded(testString);
    expect(pseudoList.length).toBeGreaterThan(0);
    
    // Reconstruct string
    const reconstructed = Pseudonym.toStringPadded(pseudoList);
    expect(testString).toEqual(reconstructed);
    
    // Test data point string padding
    const dataList = DataPoint.fromStringPadded(testString);
    expect(dataList.length).toBeGreaterThan(0);
    
    // Reconstruct string
    const reconstructedData = DataPoint.toStringPadded(dataList);
    expect(testString).toEqual(reconstructedData);
});

test('test bytes padding operations', async () => {
    const testBytes = new Uint8Array(Buffer.from("Hello, World! This is a test byte array for padding."));
    
    // Test pseudonym bytes padding
    const pseudoList = Pseudonym.fromBytesPadded(testBytes);
    expect(pseudoList.length).toBeGreaterThan(0);
    
    // Reconstruct bytes
    const reconstructed = Pseudonym.toBytesPadded(pseudoList);
    expect(new Uint8Array(reconstructed)).toEqual(testBytes);
    
    // Test data point bytes padding
    const dataList = DataPoint.fromBytesPadded(testBytes);
    expect(dataList.length).toBeGreaterThan(0);
    
    // Reconstruct bytes
    const reconstructedData = DataPoint.toBytesPadded(dataList);
    expect(new Uint8Array(reconstructedData)).toEqual(testBytes);
});

test('test fixed size bytes operations', async () => {
    // Create 16-byte test data
    const testBytes = new Uint8Array(Buffer.from("1234567890abcdef")); // Exactly 16 bytes
    
    // Test pseudonym from/as bytes
    const pseudo = Pseudonym.fromBytes(testBytes);
    const reconstructed = pseudo.asBytes();
    expect(reconstructed).not.toBeNull();
    expect(new Uint8Array(reconstructed)).toEqual(testBytes);
    
    // Test data point from/as bytes
    const data = DataPoint.fromBytes(testBytes);
    const reconstructedData = data.asBytes();
    expect(reconstructedData).not.toBeNull();
    expect(new Uint8Array(reconstructedData)).toEqual(testBytes);
});

test('test encrypted types encoding', async () => {
    // Setup
    const globalKeys = makeGlobalKeys();
    const secret = new Uint8Array(Buffer.from("secret"));
    const encSecret = new EncryptionSecret(secret);
    const sessionKeys = makeSessionKeys(globalKeys.secret, "session", encSecret);
    
    // Create encrypted pseudonym
    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, sessionKeys.public);
    
    // Test byte encoding/decoding
    const encoded = encPseudo.encode();
    const decoded = EncryptedPseudonym.decode(encoded);
    expect(decoded).not.toBeNull();
    
    // Test base64 encoding/decoding
    const b64Str = encPseudo.asBase64();
    const decodedB64 = EncryptedPseudonym.fromBase64(b64Str);
    expect(decodedB64).not.toBeNull();
    
    // Verify both decode to same plaintext
    const dec1 = decryptPseudonym(decoded, sessionKeys.secret);
    const dec2 = decryptPseudonym(decodedB64, sessionKeys.secret);
    expect(pseudo.asHex()).toEqual(dec1.asHex());
    expect(pseudo.asHex()).toEqual(dec2.asHex());
    
    // Test same for encrypted data point
    const data = DataPoint.random();
    const encData = encryptData(data, sessionKeys.public);
    
    const encodedData = encData.encode();
    const decodedData = EncryptedDataPoint.decode(encodedData);
    expect(decodedData).not.toBeNull();
    
    const decData = decryptData(decodedData, sessionKeys.secret);
    expect(data.asHex()).toEqual(decData.asHex());
});

test('test key generation consistency', async () => {
    const secret = new Uint8Array(Buffer.from("consistent_secret"));
    const encSecret = new EncryptionSecret(secret);
    
    // Generate same global keys multiple times (they should be random)
    const keys1 = makeGlobalKeys();
    const keys2 = makeGlobalKeys();
    expect(keys1.public.asHex()).not.toEqual(keys2.public.asHex());
    
    // Generate same session keys with same inputs (should be deterministic)
    const globalKeys = makeGlobalKeys();
    const session1a = makeSessionKeys(globalKeys.secret, "session1", encSecret);
    const session1b = makeSessionKeys(globalKeys.secret, "session1", encSecret);
    
    // Access GroupElement directly from SessionPublicKey (it has property '0')
    expect(session1a.public[0].asHex()).toEqual(session1b.public[0].asHex());
    
    // Different session names should give different keys
    const session2 = makeSessionKeys(globalKeys.secret, "session2", encSecret);
    expect(session1a.public[0].asHex()).not.toEqual(session2.public[0].asHex());
});

test('test global public key operations', async () => {
    // Create a global public key from existing test
    const globalKeys = makeGlobalKeys();
    const pubKey = globalKeys.public;
    
    // Test hex operations
    const hexStr = pubKey.asHex();
    const decoded = GlobalPublicKey.fromHex(hexStr);
    expect(decoded).not.toBeNull();
    expect(hexStr).toEqual(decoded.asHex());
});

test('test batch transcrypt', async () => {
    const globalKeys = makeGlobalKeys();
    const globalPublicKey = globalKeys.public;
    const globalPrivateKey = globalKeys.secret;

    const secret = Uint8Array.from(Buffer.from("secret"))

    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const domain1 = "domain1";
    const session1 = "session1";
    const domain2 = "domain2";
    const session2 = "session2";

    const pseudoInfo = new PseudonymizationInfo(domain1, domain2, session1, session2, pseudoSecret, encSecret);

    const session1Keys = makeSessionKeys(globalPrivateKey, session1, encSecret);
    const session2Keys = makeSessionKeys(globalPrivateKey, session2, encSecret);

    const messages = [];

    for (let i = 0; i < 10; i++) {
        const dataPoints = [];
        const pseudonyms = [];

        for (let j = 0; j < 3; j++) {
            dataPoints.push(encryptData(
                new DataPoint(GroupElement.random()),
                session1Keys.public,
            ));

            pseudonyms.push(encryptPseudonym(
                new Pseudonym(GroupElement.random()),
                session1Keys.public,
            ));
        }

        const entityData = new EncryptedEntityData(pseudonyms, dataPoints);
        messages.push(entityData);
    }
    const transcrypted = transcryptBatch(messages, pseudoInfo);
    expect(transcrypted.length).toEqual(messages.length);
    
    // Verify structure is maintained
    for (let i = 0; i < transcrypted.length; i++) {
        expect(transcrypted[i].pseudonyms.length).toEqual(3);
        expect(transcrypted[i].data_points.length).toEqual(3);
    }
})