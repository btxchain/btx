// Shared helpers for exercising the btx-pqc WASM module from Node.
// Used by test-wasm.mjs (functional tests) and print-wasm-vectors.mjs
// (parity vectors diffed against the native library in CI).

import createBtxPqcModule from '../dist/btx-pqc.mjs';

export const ALGO = { ML_DSA_44: 1, SLH_DSA_128S: 2 };

export const modPromise = createBtxPqcModule();

export function keygen(mod, algo, entropy) {
  const pkSize = mod._btx_pqc_public_key_size(algo);
  const skSize = mod._btx_pqc_secret_key_size(algo);
  const pkPtr = mod._malloc(pkSize);
  const skPtr = mod._malloc(skSize);
  const entPtr = mod._malloc(entropy.length);
  mod.HEAPU8.set(entropy, entPtr);
  const rc = mod._btx_pqc_keygen(algo, pkPtr, skPtr, entPtr, entropy.length);
  if (rc !== 0) throw new Error(`keygen rc=${rc}`);
  const pk = mod.HEAPU8.slice(pkPtr, pkPtr + pkSize);
  const sk = mod.HEAPU8.slice(skPtr, skPtr + skSize);
  mod.HEAPU8.fill(0, skPtr, skPtr + skSize);
  mod.HEAPU8.fill(0, entPtr, entPtr + entropy.length);
  mod._free(pkPtr); mod._free(skPtr); mod._free(entPtr);
  return { pk, sk };
}

export function sign(mod, algo, sk, msg, rnd, fips205 = 0) {
  const sigCap = mod._btx_pqc_signature_size(algo);
  const skPtr = mod._malloc(sk.length);
  const msgPtr = mod._malloc(msg.length);
  const rndPtr = rnd ? mod._malloc(rnd.length) : 0;
  const sigPtr = mod._malloc(sigCap);
  const sigLenPtr = mod._malloc(4);
  mod.HEAPU8.set(sk, skPtr);
  mod.HEAPU8.set(msg, msgPtr);
  if (rnd) mod.HEAPU8.set(rnd, rndPtr);
  mod.setValue(sigLenPtr, sigCap, 'i32');
  const rc = mod._btx_pqc_sign(algo, skPtr, sk.length, msgPtr, msg.length,
                               rndPtr, rnd ? rnd.length : 0, sigPtr, sigLenPtr, fips205);
  if (rc !== 0) throw new Error(`sign rc=${rc}`);
  const sigLen = mod.getValue(sigLenPtr, 'i32');
  const sig = mod.HEAPU8.slice(sigPtr, sigPtr + sigLen);
  mod.HEAPU8.fill(0, skPtr, skPtr + sk.length);
  [skPtr, msgPtr, sigPtr, sigLenPtr].forEach(p => mod._free(p));
  if (rndPtr) mod._free(rndPtr);
  return sig;
}

export function verify(mod, algo, pk, msg, sig, fips205 = 0) {
  const pkPtr = mod._malloc(pk.length);
  const msgPtr = mod._malloc(msg.length);
  const sigPtr = mod._malloc(sig.length);
  mod.HEAPU8.set(pk, pkPtr);
  mod.HEAPU8.set(msg, msgPtr);
  mod.HEAPU8.set(sig, sigPtr);
  const rc = mod._btx_pqc_verify(algo, pkPtr, pk.length, msgPtr, msg.length, sigPtr, sig.length, fips205);
  [pkPtr, msgPtr, sigPtr].forEach(p => mod._free(p));
  return rc === 0;
}

export const hex = (u8) => Buffer.from(u8).toString('hex');

/** The fixed test entropy shared with test/native_parity.c — keep in sync. */
export function fixedEntropy() {
  const entropy = new Uint8Array(128);
  for (let i = 0; i < 128; i++) entropy[i] = (i * 7 + 13) & 0xff;
  return entropy;
}
