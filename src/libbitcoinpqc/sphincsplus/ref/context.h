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
     * entry points from the caller's fips205 flag. */
    uint8_t fips205;

#ifdef SPX_SHA2
    // sha256 state that absorbed pub_seed
    uint8_t state_seeded[40];

# if SPX_SHA512
    // sha512 state that absorbed pub_seed
    uint8_t state_seeded_512[72];
# endif
#endif

#ifdef SPX_HARAKA
    uint64_t tweaked512_rc64[10][8];
    uint32_t tweaked256_rc32[10][8];
#endif
} spx_ctx;

#endif
