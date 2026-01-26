const {GroupElement, ScalarNonZero, encrypt, decrypt, rekey, reshuffle, rsk} = require("../../pkg/libpep.js");

describe('ElGamal encryption', () => {
    test('encryption decryption', async () => {
        const G = GroupElement.G();
        const y = ScalarNonZero.random();
        const Y = G.mul(y);
        const m = GroupElement.random();
        const encrypted = encrypt(m, Y);
        const decrypted = decrypt(encrypted, y);
        expect(m.toHex()).toEqual(decrypted.toHex());
    });
});

describe('PEP primitives', () => {
    test('rekey', async () => {
        const G = GroupElement.G();
        const y = ScalarNonZero.random();
        const Y = G.mul(y);

        const k = ScalarNonZero.random();
        const m = GroupElement.random();
        const encrypted = encrypt(m, Y);
        const rekeyed = rekey(encrypted, k);
        expect(rekeyed).not.toBeNull();
        expect(rekeyed).not.toEqual(encrypted);

        const ky = k.mul(y);
        const decrypted = decrypt(rekeyed, ky);

        expect(m.toHex()).toEqual(decrypted.toHex());
    });

    test('reshuffle', async () => {
        const G = GroupElement.G();
        const y = ScalarNonZero.random();
        const Y = G.mul(y);

        const s = ScalarNonZero.random();
        const m = GroupElement.random();
        const encrypted = encrypt(m, Y);
        const reshuffled = reshuffle(encrypted, s);

        const decrypted = decrypt(reshuffled, y);
        const expected = m.mul(s);

        expect(decrypted.toHex()).toEqual(expected.toHex());
    });

    test('rsk combined', async () => {
        const G = GroupElement.G();
        const y = ScalarNonZero.random();
        const Y = G.mul(y);

        const s = ScalarNonZero.random();
        const k = ScalarNonZero.random();
        const m = GroupElement.random();
        const encrypted = encrypt(m, Y);

        const rskResult = rsk(encrypted, s, k);
        const newSecret = k.mul(y);
        const decrypted = decrypt(rskResult, newSecret);

        const expected = m.mul(s);
        expect(decrypted.toHex()).toEqual(expected.toHex());
    });
});
