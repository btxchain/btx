# libbitcoinpqc → WebAssembly

Builds the BTX post-quantum signature library (ML-DSA-44 / Dilithium and
SLH-DSA-SHAKE-128s / SPHINCS+, portable C reference implementations) as a
WebAssembly module usable in browsers (iOS Safari, Android Chrome, desktop)
and Node.

This is the crypto core behind the btx.dev in-browser wallet generator
(see `btx-www/docs/specs/wasm-pq-wallet-generator.md`).

## Build

```sh
# Requires Emscripten (emcc) on PATH
./build-wasm.sh            # -> dist/btx-pqc.js + dist/btx-pqc.wasm
```

Outputs:

| File | Description |
|---|---|
| `dist/btx-pqc.js` | ES6 loader glue exporting the `createBtxPqcModule()` factory |
| `dist/btx-pqc.wasm` | The WebAssembly module (~55 KB) |

Properties: single-threaded, no filesystem (`-sFILESYSTEM=0`), no OS RNG —
all entropy is caller-supplied (`CUSTOM_RANDOMBYTES=1`), satisfied in
browsers by `crypto.getRandomValues()`. No COOP/COEP headers required.

## Exported ABI (flat, struct-free — see `wasm_shim.c`)

Algorithm ids are `bitcoin_pqc_algorithm_t` values: `1` = ML-DSA-44,
`2` = SLH-DSA-SHAKE-128s. All return codes are `bitcoin_pqc_error_t`
(0 = OK).

```
btx_pqc_public_key_size(algo) -> size
btx_pqc_secret_key_size(algo) -> size
btx_pqc_signature_size(algo)  -> size
btx_pqc_keygen(algo, pk_out, sk_out, entropy, entropy_len>=128) -> rc
btx_pqc_sign(algo, sk, sk_len, msg, msg_len, rnd, rnd_len,
             sig_out, sig_len_inout, slhdsa_fips205) -> rc
btx_pqc_verify(algo, pk, pk_len, msg, msg_len, sig, sig_len,
               slhdsa_fips205) -> rc
plus malloc / free for buffer management.
```

Keygen is fully deterministic in the caller-supplied entropy: the same
128 bytes always produce the same keypair, byte-identical to the native
library (`CPQKey::MakeDeterministicKey` / `bitcoin_pqc_keygen`). CI diffs
native vs WASM vectors to enforce this.

## The `randombytes` signature collision (why compile groups exist)

The vendored Dilithium and SPHINCS+ cores both declare a global
`randombytes` with **incompatible prototypes** (`size_t` vs
`unsigned long long` length). Native ABIs paper over this; WebAssembly's
exact function typing would trap at runtime. `build-wasm.sh` therefore
compiles the two cores as separate groups with `-Drandombytes=...` renames
and links `wasm_randombytes.c`, which provides both correctly-typed
implementations routed to each algorithm's caller-supplied entropy state
(replacing the native `randombytes_custom.c` pair).

## Tests

```sh
node test/test-wasm.mjs            # sizes, determinism, sign/verify roundtrips
node test/print-wasm-vectors.mjs   # parity vectors (CI diffs vs test/native_parity.c)
```

CI: `.github/workflows/libbitcoinpqc-wasm.yml` builds the module, runs the
functional tests, builds the native library, and asserts native and WASM
keygen produce identical output for identical entropy.

## JS usage sketch

```js
import createBtxPqcModule from './btx-pqc.js';
const mod = await createBtxPqcModule();

const entropy = crypto.getRandomValues(new Uint8Array(128));
const pkPtr = mod._malloc(1312), skPtr = mod._malloc(2560), entPtr = mod._malloc(128);
mod.HEAPU8.set(entropy, entPtr);
if (mod._btx_pqc_keygen(1, pkPtr, skPtr, entPtr, 128) !== 0) throw new Error('keygen failed');
const pubkey = mod.HEAPU8.slice(pkPtr, pkPtr + 1312);
const seckey = mod.HEAPU8.slice(skPtr, skPtr + 2560);
mod.HEAPU8.fill(0, skPtr, skPtr + 2560);  // zeroize before free
mod.HEAPU8.fill(0, entPtr, entPtr + 128);
[pkPtr, skPtr, entPtr].forEach(p => mod._free(p));
```
