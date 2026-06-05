#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stdint.h>

#include "params.h"

typedef struct {
    uint8_t pub_seed[SPX_N];
    uint8_t sk_seed[SPX_N];

    /* BTX: when nonzero, derive FORS indices using the finalized FIPS-205 base_2b
     * (big-endian / MSB-first) convention instead of the legacy round-3.x SPHINCS+
     * (little-endian) message_to_indices. Set per call by the SLH-DSA sign/verify
     * entry points from the caller's fips205 flag. Must match the ref variant so
     * arm64 (shake-a64) and portable (ref) nodes agree on consensus. */
    uint8_t fips205;
} spx_ctx;

#endif
