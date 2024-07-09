const wasm = require('../pkg/libpep');

test('example test', async () => {
    const result = wasm.GroupElement.random();
    console.log(result);
});
