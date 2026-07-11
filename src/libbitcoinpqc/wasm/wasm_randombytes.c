/**
 * @file wasm_randombytes.c
 * @brief WASM-safe randombytes providers for the Dilithium and SPHINCS+ cores.
 *
 * The vendored Dilithium and SPHINCS+ reference implementations both declare a
 * global `randombytes` symbol — with INCOMPATIBLE prototypes:
 *
 *   dilithium/ref/randombytes.h:   void randombytes(uint8_t *out, size_t outlen);
 *   sphincsplus/ref/randombytes.h: void randombytes(unsigned char *x, unsigned long long xlen);
 *
 * On native targets the ABI papers over the mismatch (and static-archive pull
 * order picks a single definition). WebAssembly enforces exact function
 * signatures, so the shared symbol would trap at runtime. The WASM build
 * therefore renames the symbol per compile group (-Drandombytes=...) and this
 * file provides both correctly-typed implementations, each routing to its own
 * algorithm's caller-supplied entropy state — the same routing the two
 * randombytes_custom.c files implement for native builds.
 */

#include <stddef.h>
#include <stdint.h>

/* Implemented in src/ml_dsa/utils.c (thread-local caller-supplied entropy). */
extern void custom_randombytes_impl(uint8_t *out, size_t outlen);

/* Implemented in src/slh_dsa/utils.c (thread-local caller-supplied entropy). */
extern void custom_slh_randombytes_impl(uint8_t *out, size_t outlen);

/* Dilithium compile group is built with -Drandombytes=btx_mldsa_randombytes. */
void btx_mldsa_randombytes(uint8_t *out, size_t outlen)
{
    custom_randombytes_impl(out, outlen);
}

/* SPHINCS+ compile group is built with -Drandombytes=btx_slhdsa_randombytes. */
void btx_slhdsa_randombytes(unsigned char *x, unsigned long long xlen)
{
    custom_slh_randombytes_impl((uint8_t *)x, (size_t)xlen);
}
