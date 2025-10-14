const {
    Attribute,
    GroupElement,
    makeDistributedGlobalKeys,
    PEPSystem,
    PEPClient,
    Pseudonym,
} = require("../../pkg/libpep.js");

test('n_pep', async () => {
    const n = 3;

    // Create distributed global keys.
    const [globalPublicKeys, blindedGlobalKeys, blindingFactors] = makeDistributedGlobalKeys(n);

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

    // Generate session key shares using the convenience method.
    const sksA1 = systems.map(system => system.sessionKeyShares(sessionA1));
    const sksB1 = systems.map(system => system.sessionKeyShares(sessionB1));

    // Create PEP clients using the standard constructor.
    const clientA = new PEPClient(
        blindedGlobalKeys,
        sksA1
    );
    const clientB = new PEPClient(
        blindedGlobalKeys,
        sksB1
    );

    // Generate random pseudonym and data point.
    const pseudonym = Pseudonym.random();
    const data = new Attribute(GroupElement.random());

    // Encrypt pseudonym and data.
    const encPseudo = clientA.encryptPseudonym(pseudonym);
    const encData = clientA.encryptData(data);

    // Transcrypt pseudonym and rekey data.
    const transcryptedPseudo = systems.reduce((acc, system) =>
        system.pseudonymize(acc, system.pseudonymizationInfo(domainA, domainB, sessionA1, sessionB1)), encPseudo);

    const transcryptedData = systems.reduce((acc, system) =>
        system.rekey(acc, system.attributeRekeyInfo(sessionA1, sessionB1)), encData);

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