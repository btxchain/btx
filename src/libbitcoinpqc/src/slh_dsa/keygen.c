#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/slh_dsa.h"

/*
 * This file implements the key generation function for SLH-DSA-Shake-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ implementation */
#if defined(SPHINCSPLUS_VARIANT_SHAKE_A64)
#include "../../sphincsplus/shake-a64/api.h"
#include "../../sphincsplus/shake-a64/randombytes.h"
#include "../../sphincsplus/shake-a64/params.h"
#elif defined(SPHINCSPLUS_VARIANT_REF)
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/randombytes.h"
#include "../../sphincsplus/ref/params.h"
#else
#error "SPHINCS+ variant not configured"
#endif

/*
 * External declaration for the random data utilities
 * These are implemented in src/slh_dsa/utils.c
 */
extern void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size);
extern void slh_dsa_setup_custom_random(void);
extern void slh_dsa_restore_original_random(void);

int slh_dsa_shake_128s_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!pk || !sk || !random_data || random_data_size < 128) {
        return -1;
    }

    /*
     * For fully deterministic key generation, use the first 3*SPX_N bytes
     * of the random data directly as the seed instead of going through
     * the random data wrapper.
     */
    return crypto_sign_seed_keypair(pk, sk, random_data);
}
