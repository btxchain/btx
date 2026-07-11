// Functional tests for the btx-pqc WASM build: sizes, deterministic keygen,
// sign/verify roundtrips (both algorithms, both SLH-DSA message modes).
// Run: node src/libbitcoinpqc/wasm/test/test-wasm.mjs   (after build-wasm.sh)

import { ALGO, modPromise, keygen, sign, verify, hex, fixedEntropy } from './pqc.mjs';

const mod = await modPromise;

let failures = 0;
const check = (name, cond) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}`); if (!cond) failures++; };

const entropy = fixedEntropy();

// 1. Sizes (must match src/pqkey.h constants)
check('ML-DSA-44 pk size 1312', mod._btx_pqc_public_key_size(ALGO.ML_DSA_44) === 1312);
check('ML-DSA-44 sk size 2560', mod._btx_pqc_secret_key_size(ALGO.ML_DSA_44) === 2560);
check('ML-DSA-44 sig size 2420', mod._btx_pqc_signature_size(ALGO.ML_DSA_44) === 2420);
check('SLH-DSA-128s pk size 32', mod._btx_pqc_public_key_size(ALGO.SLH_DSA_128S) === 32);
check('SLH-DSA-128s sk size 64', mod._btx_pqc_secret_key_size(ALGO.SLH_DSA_128S) === 64);
check('SLH-DSA-128s sig size 7856', mod._btx_pqc_signature_size(ALGO.SLH_DSA_128S) === 7856);

// 2. Keygen determinism
const ml1 = keygen(mod, ALGO.ML_DSA_44, entropy);
const ml2 = keygen(mod, ALGO.ML_DSA_44, entropy);
check('ML-DSA keygen deterministic (pk)', hex(ml1.pk) === hex(ml2.pk));
check('ML-DSA keygen deterministic (sk)', hex(ml1.sk) === hex(ml2.sk));
const entropy2 = entropy.slice(); entropy2[0] ^= 1;
const ml3 = keygen(mod, ALGO.ML_DSA_44, entropy2);
check('ML-DSA different entropy -> different key', hex(ml1.pk) !== hex(ml3.pk));

const slh1 = keygen(mod, ALGO.SLH_DSA_128S, entropy);
const slh2 = keygen(mod, ALGO.SLH_DSA_128S, entropy);
check('SLH-DSA keygen deterministic (pk)', hex(slh1.pk) === hex(slh2.pk));
check('SLH-DSA keygen deterministic (sk)', hex(slh1.sk) === hex(slh2.sk));
// Structure per crypto_sign_seed_keypair: sk = SK.seed||SK.prf||PK.seed||PK.root
check('SLH-DSA sk embeds entropy[0:48]', hex(slh1.sk.slice(0, 48)) === hex(entropy.slice(0, 48)));
check('SLH-DSA pk = sk[32:64]', hex(slh1.pk) === hex(slh1.sk.slice(32, 64)));

// 3. Sign/verify roundtrips
const msg = new Uint8Array(32); msg.fill(0xab);
const rnd = new Uint8Array(128); rnd.fill(0x42);
const msgBad = msg.slice(); msgBad[0] ^= 1;

const mlSig = sign(mod, ALGO.ML_DSA_44, ml1.sk, msg, rnd);
check('ML-DSA sig length 2420', mlSig.length === 2420);
check('ML-DSA verify OK', verify(mod, ALGO.ML_DSA_44, ml1.pk, msg, mlSig));
check('ML-DSA tampered msg rejected', !verify(mod, ALGO.ML_DSA_44, ml1.pk, msgBad, mlSig));
check('ML-DSA wrong key rejected', !verify(mod, ALGO.ML_DSA_44, ml3.pk, msg, mlSig));

const slhSig = sign(mod, ALGO.SLH_DSA_128S, slh1.sk, msg, rnd, 0);
check('SLH-DSA sig length 7856', slhSig.length === 7856);
check('SLH-DSA verify OK', verify(mod, ALGO.SLH_DSA_128S, slh1.pk, msg, slhSig, 0));
check('SLH-DSA tampered msg rejected', !verify(mod, ALGO.SLH_DSA_128S, slh1.pk, msgBad, slhSig, 0));

// FIPS-205 pure-mode context wrap (SLH-DSA only)
const slhSigF = sign(mod, ALGO.SLH_DSA_128S, slh1.sk, msg, rnd, 1);
check('SLH-DSA fips205 verify OK', verify(mod, ALGO.SLH_DSA_128S, slh1.pk, msg, slhSigF, 1));
check('SLH-DSA fips205/legacy mode mismatch rejected', !verify(mod, ALGO.SLH_DSA_128S, slh1.pk, msg, slhSigF, 0));

console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
