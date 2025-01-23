const {
    DataPoint,
    GroupElement,
    makeGlobalKeys, makeBlindedGlobalSecretKey, PEPSystem, PEPClient, Pseudonym, BlindingFactor,
} = require("../../pkg/libpep.js");

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

    // Create pseudonymization domains and encryption contexts.
    const domainA = "user-a";
    const domainB = "user-b";
    const sessionA1 = "session-a1";
    const sessionB1 = "session-b1";

    // Generate session key shares.
    const sksA1 = systems.map(system => system.sessionKeyShare(sessionA1));
    const sksB1 = systems.map(system => system.sessionKeyShare(sessionB1));

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
        system.pseudonymize(acc, system.pseudonymizationInfo(domainA, domainB, sessionA1, sessionB1)), encPseudo);

    const transcryptedData = systems.reduce((acc, system) =>
        system.rekey(acc, system.rekeyInfo(sessionA1, sessionB1)), encData);

    // Decrypt pseudonym and data.
    const decPseudo = clientB.decryptPseudonym(transcryptedPseudo);
    const decData = clientB.decryptData(transcryptedData);

    // Assert equality and inequality.
    expect(decData.asHex()).toEqual(data.asHex());
    expect(decPseudo).not.toEqual(pseudonym);

    // Reverse pseudonymization.
    const revPseudonymized = systems.reduce((acc, system) =>
        system.pseudonymize(acc, system.pseudonymizationInfo(domainA, domainB, sessionA1, sessionB1).rev()), transcryptedPseudo);

    const revDecPseudo = clientA.decryptPseudonym(revPseudonymized);
    expect(revDecPseudo.asHex()).toEqual(pseudonym.asHex());
});