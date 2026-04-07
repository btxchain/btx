#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/slh_dsa.h"

/*
 * This file implements the verification function for SLH-DSA-Shake-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ implementation */
#if defined(SPHINCSPLUS_VARIANT_SHAKE_A64)
#include "../../sphincsplus/shake-a64/api.h"
#elif defined(SPHINCSPLUS_VARIANT_REF)
#include "../../sphincsplus/ref/api.h"
#else
#error "SPHINCS+ variant not configured"
#endif

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
