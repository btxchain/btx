#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/slh_dsa.h"

/*
 * This file integrates the reference implementation of SLH-DSA-Shake-128s (SPHINCS+)
 * We need to adapt the reference implementation API to our library's API.
 */

/* Include necessary headers from SPHINCS+ reference implementation */
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/randombytes.h"
#include "../../sphincsplus/ref/params.h"
#include "../../sphincsplus/ref/fips202.h"

/* Define the parameter set we're using */
#define CRYPTO_ALGNAME "SPHINCS+-shake-128s"

/* Provide a custom random bytes function that uses user-provided entropy */
static uint8_t *g_random_data = NULL;
static size_t g_random_data_size = 0;
static size_t g_random_data_offset = 0;

/* Initialize the random data source */
static void init_random_source(const uint8_t *random_data, size_t random_data_size) {
    g_random_data = (uint8_t *)random_data;
    g_random_data_size = random_data_size;
    g_random_data_offset = 0;
}

/* Custom randombytes implementation that uses the user-provided entropy */
static void custom_randombytes(uint8_t *out, size_t outlen) {
    if (g_random_data == NULL || g_random_data_size == 0) {
        /* This should not happen as we check for random data before keygen/sign */
        memset(out, 0, outlen);
        return;
    }

    size_t remaining = g_random_data_size - g_random_data_offset;

    if (outlen > remaining) {
        /* If we need more random bytes than available, we cycle through the provided data */
        size_t position = 0;

        while (position < outlen) {
            size_t to_copy = (outlen - position < remaining) ? outlen - position : remaining;
            memcpy(out + position, g_random_data + g_random_data_offset, to_copy);

            position += to_copy;
            g_random_data_offset = (g_random_data_offset + to_copy) % g_random_data_size;
            remaining = g_random_data_size - g_random_data_offset;
        }
    } else {
        /* We have enough random data */
        memcpy(out, g_random_data + g_random_data_offset, outlen);
        g_random_data_offset = (g_random_data_offset + outlen) % g_random_data_size;
    }
}

/* Keep track of the original randombytes function */
static void (*original_randombytes)(uint8_t *, size_t) = NULL;

/* Set up the custom random bytes function */
static void setup_custom_random() {
    /* Store the original function */
    if (original_randombytes == NULL) {
        original_randombytes = randombytes;
    }

    /* Override with our custom implementation */
    randombytes = custom_randombytes;
}

/* Restore the original random bytes function */
static void restore_original_random() {
    if (original_randombytes != NULL) {
        randombytes = original_randombytes;
    }

    /* Clear the global state */
    g_random_data = NULL;
    g_random_data_size = 0;
    g_random_data_offset = 0;
}

int slh_dsa_shake_128s_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!pk || !sk || !random_data || random_data_size < 128) {
        return -1;
    }

    /* Set up custom random bytes function with user-provided entropy */
    init_random_source(random_data, random_data_size);
    setup_custom_random();

    /* Call the reference implementation's key generation function */
    int result = crypto_sign_keypair(pk, sk);

    /* Restore original random bytes function */
    restore_original_random();

    return result;
}

int slh_dsa_shake_128s_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!sig || !siglen || !m || !sk) {
        return -1;
    }

    /* Use provided random data if available */
    if (random_data && random_data_size >= 64) {
        init_random_source(random_data, random_data_size);
        setup_custom_random();
    }

    /* The reference implementation prepends the message to the signature
     * but we want just the signature, so we need to use the detached API
     */
    unsigned long long temp_siglen;
    int result = crypto_sign_signature(sig, &temp_siglen, m, mlen, sk);
    *siglen = (size_t)temp_siglen;

    /* Restore original random bytes function if we changed it */
    if (random_data && random_data_size >= 64) {
        restore_original_random();
    }

    return result;
}

int slh_dsa_shake_128s_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    if (!sig || !m || !pk) {
        return -1;
    }

    /* Call the reference implementation's verification function */
    return crypto_sign_verify(sig, siglen, m, mlen, pk);
}
