const {
    DataPoint,
    GroupElement,
    makeGlobalKeys, makeBlindedGlobalSecretKey, PEPSystem, PEPClient, Pseudonym, BlindingFactor,
} = require("../../../pkg");

test('n_pep', async () => {
    const n = 3;

    // Create global keys.
    const keyPair = makeGlobalKeys();
    const globalPublicKey = keyPair.public;
    const globalSecret = keyPair.secret

    const blindingFactors = Array.from({ length: n }, () => BlindingFactor.random());

    const blindingFactorsCopy = blindingFactors.map(bf => bf.clone());
    const blindedGlobalSecretKey = makeBlindedGlobalSecretKey(globalSecret, blindingFactorsCopy);

    // Initialize systems.
    const systems = Array.from({ length: n }, (_, i) => {
        const pseudonymizationSecret = `secret-${i}`;
        const encryptionSecret = `secret-${i}`;
        const blindingFactor = blindingFactors[i];
        return new PEPSystem(pseudonymizationSecret, encryptionSecret, blindingFactor);
    });

    // Create pseudonymization and encryption contexts.
    const pcA = "user-a";
    const pcB = "user-b";
    const ecA1 = "session-a1";
    const ecB1 = "session-b1";

    // Generate session key shares.
    const sksA1 = systems.map(system => system.sessionKeyShare(ecA1));
    const sksB1 = systems.map(system => system.sessionKeyShare(ecB1));

    // Create PEP clients.
    const clientA = new PEPClient(blindedGlobalSecretKey, sksA1);
    const clientB = new PEPClient(blindedGlobalSecretKey, sksB1);

    // Generate random pseudonym and data point.
    const pseudonym = Pseudonym.random();
    const data = new DataPoint(GroupElement.random());

    // Encrypt pseudonym and data.
    const encPseudo = clientA.encryptPseudonym(pseudonym);
    const encData = clientA.encryptData(data);

    // Transcrypt pseudonym and rekey data.
    const transcryptedPseudo = systems.reduce((acc, system) =>
        system.pseudonymize(acc, system.pseudonymizationInfo(pcA, pcB, ecA1, ecB1)), encPseudo);

    const transcryptedData = systems.reduce((acc, system) =>
        system.rekey(acc, system.rekeyInfo(ecA1, ecB1)), encData);

    // Decrypt pseudonym and data.
    const decPseudo = clientB.decryptPseudonym(transcryptedPseudo);
    const decData = clientB.decryptData(transcryptedData);

    // Assert equality and inequality.
    expect(decData.toHex()).toEqual(data.toHex());
    expect(decPseudo).not.toEqual(pseudonym);

    // Reverse pseudonymization.
    const revPseudonymized = systems.reduce((acc, system) =>
        system.pseudonymize(acc, system.pseudonymizationInfo(pcA, pcB, ecA1, ecB1).rev()), transcryptedPseudo);

    const revDecPseudo = clientA.decryptPseudonym(revPseudonymized);
    expect(revDecPseudo.toHex()).toEqual(pseudonym.toHex());
});