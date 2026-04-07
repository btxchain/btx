#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../dilithium/ref/randombytes.h"
#include "../../dilithium/ref/api.h"
#include "../../dilithium/ref/fips202.h"
#include "../../dilithium/ref/params.h"
#include "libbitcoinpqc/ml_dsa.h"

#if defined(_MSC_VER)
#define BTX_THREAD_LOCAL __declspec(thread)
#else
#define BTX_THREAD_LOCAL _Thread_local
#endif

/*
 * This file implements utility functions for ML-DSA-44 (CRYSTALS-Dilithium)
 * particularly related to random data handling
 */

/* Provide a custom random bytes function that uses user-provided entropy.
 * Thread-local so parallel signing threads each get their own random state. */
static BTX_THREAD_LOCAL const uint8_t *g_random_data = NULL;
static BTX_THREAD_LOCAL size_t g_random_data_size = 0;
static BTX_THREAD_LOCAL size_t g_random_data_offset = 0;

/* Initialize the random data source */
void ml_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size) {
    g_random_data = random_data;
    g_random_data_size = random_data_size;
    g_random_data_offset = 0;
}

/* Setup custom random function - this is called before keygen/sign */
void ml_dsa_setup_custom_random() {
    /* Nothing to do here, as our randombytes function is already set up */
}

/* Restore original random function - this is called after keygen/sign */
void ml_dsa_restore_original_random() {
    /* Clear the global state */
    g_random_data = NULL;
    g_random_data_size = 0;
    g_random_data_offset = 0;
}

/* This function is called from our custom randombytes implementation */
void custom_randombytes_impl(uint8_t *out, size_t outlen) {
    /* If out is NULL or outlen is 0, nothing to do */
    if (!out || outlen == 0) {
        return;
    }

    /* If we don't have custom random data, use system randomness */
    if (g_random_data == NULL || g_random_data_size == 0) {
        /* Fall back to system randomness */
        FILE *f = fopen("/dev/urandom", "r");
        if (!f) {
            /* If we can't open /dev/urandom, just fill with zeros */
            memset(out, 0, outlen);
            return;
        }

        size_t bytes_read = fread(out, 1, outlen, f);
        fclose(f);

        /* If we can't read enough data, fill remaining with zeros */
        if (bytes_read < outlen) {
            memset(out + bytes_read, 0, outlen - bytes_read);
        }

        return;
    }

    /* Otherwise use our provided random data */
    size_t total_copied = 0;

    /* Copy data until we've filled the output buffer */
    while (total_copied < outlen) {
        /* Calculate amount to copy */
        size_t amount = outlen - total_copied;
        if (amount > g_random_data_size - g_random_data_offset) {
            amount = g_random_data_size - g_random_data_offset;
        }

        /* Copy the data */
        memcpy(out + total_copied, g_random_data + g_random_data_offset, amount);

        /* Update positions */
        total_copied += amount;
        g_random_data_offset += amount;

        /* Wrap around if needed */
        if (g_random_data_offset >= g_random_data_size) {
            g_random_data_offset = 0;
        }
    }
}

/* Function to derive deterministic randomness from message and key */
void ml_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    /* Use SHAKE-256 to derive deterministic randomness from message and secret key */
    keccak_state state;

    /* Initialize the hash context */
    shake256_init(&state);

    /* Absorb secret key first */
    shake256_absorb(&state, sk, CRYPTO_SECRETKEYBYTES);

    /* Absorb message */
    shake256_absorb(&state, m, mlen);

    /* Finalize and extract randomness */
    shake256_finalize(&state);
    shake256_squeeze(seed, 64, &state);
}
