#!/usr/bin/env bash
# Build libbitcoinpqc as a WebAssembly module (browser + Node).
#
# Compiles the portable C reference implementations (Dilithium/ML-DSA-44 and
# SPHINCS+/SLH-DSA-SHAKE-128s) plus the libbitcoinpqc wrappers and the flat
# wasm shim into an ES6-module Emscripten build:
#
#   dist/btx-pqc.js    ES6 loader glue (createBtxPqcModule factory)
#   dist/btx-pqc.wasm  the WebAssembly module
#
# Source list, include dirs, and defines mirror ../CMakeLists.txt (the
# SPHINCSPLUS_VARIANT="ref" portable path), with one WASM-specific change:
# the Dilithium and SPHINCS+ cores declare the global `randombytes` symbol
# with incompatible prototypes (size_t vs unsigned long long length), which
# native ABIs tolerate but WASM's exact function typing does not. The build
# renames the symbol per compile group (-Drandombytes=...) and links
# wasm_randombytes.c, which provides both correctly-typed implementations
# routed to each algorithm's caller-supplied entropy state (replacing the
# two native randombytes_custom.c files).
#
# No threads, no filesystem, no OS RNG: all entropy is caller-supplied
# (CUSTOM_RANDOMBYTES=1), satisfied in browsers by crypto.getRandomValues().
#
# Requirements: emcc (Emscripten) on PATH.
# Usage: ./build-wasm.sh [outdir]   (default: ./dist)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PQC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/dist}"
OBJ_DIR="${OUT_DIR}/obj"

command -v emcc >/dev/null 2>&1 || {
    echo "error: emcc not found on PATH (install Emscripten)" >&2
    exit 1
}

mkdir -p "${OUT_DIR}" "${OBJ_DIR}"

COMMON_FLAGS=(
    -O3
    -I "${PQC_ROOT}/include"
    -I "${PQC_ROOT}/dilithium/ref"
    -I "${PQC_ROOT}/sphincsplus/ref"
    -DDILITHIUM_MODE=2
    -DPARAMS=sphincs-shake-128s
    -DCUSTOM_RANDOMBYTES=1
    -DSPHINCSPLUS_VARIANT_REF=1
)

# --- Compile groups (mirror CMakeLists.txt, SPHINCSPLUS_VARIANT="ref") ------

# Dilithium core + ML-DSA wrappers: randombytes -> btx_mldsa_randombytes
ML_DSA_GROUP=(
    dilithium/ref/sign.c
    dilithium/ref/packing.c
    dilithium/ref/polyvec.c
    dilithium/ref/poly.c
    dilithium/ref/ntt.c
    dilithium/ref/reduce.c
    dilithium/ref/rounding.c
    dilithium/ref/fips202.c
    dilithium/ref/symmetric-shake.c
    src/ml_dsa/utils.c
    src/ml_dsa/keygen.c
    src/ml_dsa/sign.c
    src/ml_dsa/verify.c
)

# SPHINCS+ core + SLH-DSA wrappers: randombytes -> btx_slhdsa_randombytes
SLH_DSA_GROUP=(
    sphincsplus/ref/address.c
    sphincsplus/ref/fors.c
    sphincsplus/ref/hash_shake.c
    sphincsplus/ref/merkle.c
    sphincsplus/ref/sign.c
    sphincsplus/ref/thash_shake_simple.c
    sphincsplus/ref/utils.c
    sphincsplus/ref/utilsx1.c
    sphincsplus/ref/wots.c
    sphincsplus/ref/wotsx1.c
    sphincsplus/ref/fips202.c
    src/slh_dsa/utils.c
    src/slh_dsa/keygen.c
    src/slh_dsa/sign.c
    src/slh_dsa/verify.c
)

# Symbol-neutral sources (no randombytes references)
COMMON_GROUP=(
    src/bitcoinpqc.c
    wasm/wasm_randombytes.c
    wasm/wasm_shim.c
)

OBJECTS=()

compile_group() {
    local rename="$1"; shift
    local extra=()
    if [[ -n "${rename}" ]]; then
        extra+=("-Drandombytes=${rename}")
    fi
    for src in "$@"; do
        local obj="${OBJ_DIR}/$(echo "${src}" | tr '/' '_').o"
        # ${extra[@]+...} guard: empty arrays trip `set -u` on bash 3.2 (macOS)
        emcc "${COMMON_FLAGS[@]}" ${extra[@]+"${extra[@]}"} -c "${PQC_ROOT}/${src}" -o "${obj}"
        OBJECTS+=("${obj}")
    done
}

echo "Compiling ML-DSA group..."
compile_group btx_mldsa_randombytes "${ML_DSA_GROUP[@]}"
echo "Compiling SLH-DSA group..."
compile_group btx_slhdsa_randombytes "${SLH_DSA_GROUP[@]}"
echo "Compiling common group..."
compile_group "" "${COMMON_GROUP[@]}"

# --- Link -------------------------------------------------------------------

EXPORTED_FUNCTIONS='_btx_pqc_keygen,_btx_pqc_sign,_btx_pqc_verify,_btx_pqc_public_key_size,_btx_pqc_secret_key_size,_btx_pqc_signature_size,_malloc,_free'

echo "Linking ${OUT_DIR}/btx-pqc.js + btx-pqc.wasm..."
emcc \
    -O3 \
    "${OBJECTS[@]}" \
    -o "${OUT_DIR}/btx-pqc.js" \
    --no-entry \
    -sMODULARIZE=1 \
    -sEXPORT_ES6=1 \
    -sEXPORT_NAME=createBtxPqcModule \
    -sENVIRONMENT=web,worker,node \
    -sFILESYSTEM=0 \
    -sALLOW_MEMORY_GROWTH=1 \
    -sINITIAL_MEMORY=16777216 \
    -sSTACK_SIZE=1048576 \
    -sEXPORTED_FUNCTIONS="${EXPORTED_FUNCTIONS}" \
    -sEXPORTED_RUNTIME_METHODS=HEAPU8,HEAPU32,getValue,setValue

rm -rf "${OBJ_DIR}"

echo
echo "Artifacts:"
ls -la "${OUT_DIR}/btx-pqc.js" "${OUT_DIR}/btx-pqc.wasm"
echo
echo "SHA-256:"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${OUT_DIR}/btx-pqc.js" "${OUT_DIR}/btx-pqc.wasm"
else
    shasum -a 256 "${OUT_DIR}/btx-pqc.js" "${OUT_DIR}/btx-pqc.wasm"
fi
