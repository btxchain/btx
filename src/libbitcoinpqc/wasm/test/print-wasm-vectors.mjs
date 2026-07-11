// Print deterministic keygen vectors from the WASM build in the exact format
// emitted by test/native_parity.c, so CI can `diff` the two outputs.

import { ALGO, modPromise, keygen, hex, fixedEntropy } from './pqc.mjs';

const mod = await modPromise;
const entropy = fixedEntropy();

const ml = keygen(mod, ALGO.ML_DSA_44, entropy);
console.log(`ML-DSA pk[0:16]: ${hex(ml.pk.slice(0, 16))}`);

const slh = keygen(mod, ALGO.SLH_DSA_128S, entropy);
console.log(`SLH-DSA pk: ${hex(slh.pk)}`);
