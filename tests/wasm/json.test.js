const {
    makeGlobalKeys,
    makeSessionKeys,
    PEPJSONBuilder,
    encryptJson,
    decryptJson,
    transcryptJsonBatch,
    TranscryptionInfo,
    PseudonymizationSecret,
    EncryptionSecret,
    PseudonymizationDomain,
    EncryptionContext,
} = require("../../pkg/libpep.js");

test('test json transcryption with builder', async () => {
    // Setup keys and secrets
    const globalKeys = makeGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(Uint8Array.from(Buffer.from("pseudo-secret")));
    const encSecret = new EncryptionSecret(Uint8Array.from(Buffer.from("encryption-secret")));

    const session = new EncryptionContext("session-1");

    const sessionKeys = makeSessionKeys(globalKeys.secret, session, encSecret);

    // Create JSON with existing data
    const patientData = {
        user_id: "user-67890",
        name: "Alice",
        age: 30,
        active: true
    };

    // Convert to PEP JSON, specifying which fields are pseudonyms
    const patientRecord = PEPJSONBuilder.fromJson(patientData, ["user_id"]).build();

    // Encrypt
    const encrypted = encryptJson(patientRecord, sessionKeys);

    // Decrypt to verify original
    const decryptedOriginal = decryptJson(encrypted, sessionKeys);
    const jsonOriginal = decryptedOriginal.toJson();
    expect(jsonOriginal.get("user_id")).toBe("user-67890");
    expect(jsonOriginal.get("name")).toBe("Alice");
    expect(jsonOriginal.get("age")).toBe(30);
    expect(jsonOriginal.get("active")).toBe(true);

    // Transcrypt from clinic A to clinic B
    const domainA = new PseudonymizationDomain("clinic-a");
    const domainB = new PseudonymizationDomain("clinic-b");

    const transcrypted = encrypted.transcrypt(
        domainA,
        domainB,
        session,
        session,
        pseudoSecret,
        encSecret
    );

    // Verify that the encrypted structures are different after transcryption
    // (The pseudonym has been transformed)
    expect(encrypted).not.toBe(transcrypted);

    // Decrypt transcrypted data
    const decryptedTranscrypted = decryptJson(transcrypted, sessionKeys);
    const jsonTranscrypted = decryptedTranscrypted.toJson();

    // Attributes should remain the same, but pseudonym should be different
    expect(jsonTranscrypted.get("name")).toBe("Alice");
    expect(jsonTranscrypted.get("age")).toBe(30);
    expect(jsonTranscrypted.get("active")).toBe(true);
    expect(jsonTranscrypted.get("user_id")).not.toBe("user-67890");
});

test('test json batch transcryption same structure', async () => {
    // Setup keys and secrets
    const globalKeys = makeGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(Uint8Array.from(Buffer.from("pseudo-secret")));
    const encSecret = new EncryptionSecret(Uint8Array.from(Buffer.from("encryption-secret")));

    const domainA = new PseudonymizationDomain("domain-a");
    const domainB = new PseudonymizationDomain("domain-b");
    const session = new EncryptionContext("session-1");

    const sessionKeys = makeSessionKeys(globalKeys.secret, session, encSecret);

    // Create two JSON values with the SAME structure using JavaScript objects
    const data1 = {
        patient_id: "patient-001",
        diagnosis: "Flu",
        temperature: 38.5
    };

    const data2 = {
        patient_id: "patient-002",
        diagnosis: "Cold",
        temperature: 37.2
    };

    // Convert to PEP JSON, specifying "patient_id" as pseudonym field
    const record1 = PEPJSONBuilder.fromJson(data1, ["patient_id"]).build();
    const record2 = PEPJSONBuilder.fromJson(data2, ["patient_id"]).build();

    // Encrypt both records
    const encrypted1 = encryptJson(record1, sessionKeys);
    const encrypted2 = encryptJson(record2, sessionKeys);

    // Verify they have the same structure
    const structure1 = encrypted1.structure();
    const structure2 = encrypted2.structure();
    expect(structure1.equals(structure2)).toBe(true);

    // Batch transcrypt (this should succeed because structures match)
    const transcryptionInfo = new TranscryptionInfo(
        domainA,
        domainB,
        session,
        session,
        pseudoSecret,
        encSecret
    );

    const transcryptedBatch = transcryptJsonBatch(
        [encrypted1, encrypted2],
        transcryptionInfo
    );

    // Verify we got 2 records back
    expect(transcryptedBatch.length).toBe(2);

    // Verify that batch transcryption succeeded and values changed
    expect(transcryptedBatch[0]).not.toBe(encrypted1);
    expect(transcryptedBatch[1]).not.toBe(encrypted2);

    // Decrypt all transcrypted values
    const decryptedBatch = transcryptedBatch.map(v => decryptJson(v, sessionKeys).toJson());

    // Sort by temperature to have a consistent order (Cold=37.2, Flu=38.5)
    decryptedBatch.sort((a, b) => a.get("temperature") - b.get("temperature"));

    // Verify the Cold patient data (lower temperature)
    expect(decryptedBatch[0].get("diagnosis")).toBe("Cold");
    expect(decryptedBatch[0].get("temperature")).toBe(37.2);
    expect(decryptedBatch[0].get("patient_id")).not.toBe("patient-002");

    // Verify the Flu patient data (higher temperature)
    expect(decryptedBatch[1].get("diagnosis")).toBe("Flu");
    expect(decryptedBatch[1].get("temperature")).toBe(38.5);
    expect(decryptedBatch[1].get("patient_id")).not.toBe("patient-001");
});

test('test json batch transcryption different structures', async () => {
    // Setup keys and secrets
    const globalKeys = makeGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(Uint8Array.from(Buffer.from("pseudo-secret")));
    const encSecret = new EncryptionSecret(Uint8Array.from(Buffer.from("encryption-secret")));

    const domainA = new PseudonymizationDomain("domain-a");
    const domainB = new PseudonymizationDomain("domain-b");
    const session = new EncryptionContext("session-1");

    const sessionKeys = makeSessionKeys(globalKeys.secret, session, encSecret);

    // Create two JSON values with DIFFERENT structures using JavaScript objects
    const data1 = {
        patient_id: "patient-001",
        diagnosis: "Flu",
        temperature: 38.5
    };

    const data2 = {
        user_id: "user-002",
        name: "Bob",
        age: 25,
        active: true
    };

    // Convert to PEP JSON with different pseudonym fields
    const record1 = PEPJSONBuilder.fromJson(data1, ["patient_id"]).build();
    const record2 = PEPJSONBuilder.fromJson(data2, ["user_id"]).build();

    // Encrypt both records
    const encrypted1 = encryptJson(record1, sessionKeys);
    const encrypted2 = encryptJson(record2, sessionKeys);

    // Verify they have different structures
    const structure1 = encrypted1.structure();
    const structure2 = encrypted2.structure();
    expect(structure1.equals(structure2)).toBe(false);

    // Attempt batch transcryption (this should throw an error because structures don't match)
    const transcryptionInfo = new TranscryptionInfo(
        domainA,
        domainB,
        session,
        session,
        pseudoSecret,
        encSecret
    );

    // Verify we get an error about structure mismatch
    expect(() => {
        transcryptJsonBatch([encrypted1, encrypted2], transcryptionInfo);
    }).toThrow(/All values must have the same structure/);
});
