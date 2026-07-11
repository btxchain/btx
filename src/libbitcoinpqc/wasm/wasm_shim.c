/**
 * @file wasm_shim.c
 * @brief Flat-ABI WebAssembly shim over libbitcoinpqc.
 *
 * Exposes struct-free wrappers around the bitcoin_pqc_* API so that
 * JavaScript callers never need to know the memory layout of
 * bitcoin_pqc_keypair_t / bitcoin_pqc_signature_t. All buffers are
 * caller-allocated (via the exported malloc/free); the shim copies key
 * and signature material into them and zeroizes/frees the library-side
 * allocations before returning.
 *
 * Algorithm ids match bitcoin_pqc_algorithm_t (bitcoinpqc.h):
 *   1 = ML-DSA-44 (BITCOIN_PQC_ML_DSA_44)
 *   2 = SLH-DSA-SHAKE-128s (BITCOIN_PQC_SLH_DSA_SHAKE_128S)
 *
 * Error codes are bitcoin_pqc_error_t values (0 = OK).
 */

#include <libbitcoinpqc/bitcoinpqc.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define WASM_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define WASM_EXPORT
#endif

/* Best-effort volatile zeroization of library-owned secret buffers before
 * bitcoin_pqc_keypair_free() returns them to the allocator. */
static void shim_memzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

WASM_EXPORT size_t btx_pqc_public_key_size(int algorithm)
{
    return bitcoin_pqc_public_key_size((bitcoin_pqc_algorithm_t)algorithm);
}

WASM_EXPORT size_t btx_pqc_secret_key_size(int algorithm)
{
    return bitcoin_pqc_secret_key_size((bitcoin_pqc_algorithm_t)algorithm);
}

WASM_EXPORT size_t btx_pqc_signature_size(int algorithm)
{
    return bitcoin_pqc_signature_size((bitcoin_pqc_algorithm_t)algorithm);
}

/**
 * Generate a keypair from caller-supplied entropy (>= 128 bytes).
 *
 * @param algorithm    bitcoin_pqc_algorithm_t id (1 or 2)
 * @param public_key   out buffer, btx_pqc_public_key_size(algorithm) bytes
 * @param secret_key   out buffer, btx_pqc_secret_key_size(algorithm) bytes
 * @param random_data  entropy buffer
 * @param random_len   entropy length (must be >= 128)
 * @return 0 on success, bitcoin_pqc_error_t on failure
 */
WASM_EXPORT int btx_pqc_keygen(
    int algorithm,
    uint8_t *public_key,
    uint8_t *secret_key,
    const uint8_t *random_data,
    size_t random_len)
{
    if (!public_key || !secret_key || !random_data) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    bitcoin_pqc_keypair_t keypair;
    memset(&keypair, 0, sizeof(keypair));

    const bitcoin_pqc_error_t result = bitcoin_pqc_keygen(
        (bitcoin_pqc_algorithm_t)algorithm, &keypair, random_data, random_len);
    if (result != BITCOIN_PQC_OK) {
        return (int)result;
    }

    const size_t pk_size = bitcoin_pqc_public_key_size((bitcoin_pqc_algorithm_t)algorithm);
    const size_t sk_size = bitcoin_pqc_secret_key_size((bitcoin_pqc_algorithm_t)algorithm);
    if (keypair.public_key_size != pk_size || keypair.secret_key_size != sk_size) {
        if (keypair.secret_key) shim_memzero(keypair.secret_key, keypair.secret_key_size);
        bitcoin_pqc_keypair_free(&keypair);
        return BITCOIN_PQC_ERROR_BAD_KEY;
    }

    memcpy(public_key, keypair.public_key, pk_size);
    memcpy(secret_key, keypair.secret_key, sk_size);

    shim_memzero(keypair.secret_key, keypair.secret_key_size);
    bitcoin_pqc_keypair_free(&keypair);
    return BITCOIN_PQC_OK;
}

/**
 * Sign a message with hedged (caller-supplied) randomness.
 *
 * @param algorithm       bitcoin_pqc_algorithm_t id (1 or 2)
 * @param secret_key      secret key bytes
 * @param secret_key_len  secret key length
 * @param message         message bytes
 * @param message_len     message length
 * @param random_data     entropy for hedged signing (may be NULL for deterministic)
 * @param random_len      entropy length (0 or >= 64 per library rules)
 * @param signature_out   out buffer, btx_pqc_signature_size(algorithm) bytes
 * @param signature_len   in/out: capacity of signature_out; set to written size
 * @param slhdsa_fips205  non-zero to apply the FIPS-205 pure-mode context wrap (SLH-DSA only)
 * @return 0 on success, bitcoin_pqc_error_t on failure
 */
WASM_EXPORT int btx_pqc_sign(
    int algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *random_data,
    size_t random_len,
    uint8_t *signature_out,
    size_t *signature_len,
    int slhdsa_fips205)
{
    if (!secret_key || !message || !signature_out || !signature_len) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    bitcoin_pqc_signature_t signature;
    memset(&signature, 0, sizeof(signature));

    const bitcoin_pqc_error_t result = bitcoin_pqc_sign_with_randomness(
        (bitcoin_pqc_algorithm_t)algorithm,
        secret_key, secret_key_len,
        message, message_len,
        random_data, random_len,
        &signature,
        slhdsa_fips205);
    if (result != BITCOIN_PQC_OK) {
        return (int)result;
    }

    if (signature.signature_size > *signature_len) {
        bitcoin_pqc_signature_free(&signature);
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }

    memcpy(signature_out, signature.signature, signature.signature_size);
    *signature_len = signature.signature_size;
    bitcoin_pqc_signature_free(&signature);
    return BITCOIN_PQC_OK;
}

/**
 * Verify a signature.
 *
 * @return 0 if the signature is valid, bitcoin_pqc_error_t otherwise
 */
WASM_EXPORT int btx_pqc_verify(
    int algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    int slhdsa_fips205)
{
    if (!public_key || !message || !signature) {
        return BITCOIN_PQC_ERROR_BAD_ARG;
    }
    return (int)bitcoin_pqc_verify(
        (bitcoin_pqc_algorithm_t)algorithm,
        public_key, public_key_len,
        message, message_len,
        signature, signature_len,
        slhdsa_fips205);
}
