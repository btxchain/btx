#include <stddef.h>
#include <stdint.h>

/*
 * Provide a custom randombytes() implementation for SPHINCS+ that routes
 * entropy requests through our BTX wrapper.
 */

#if defined(SPHINCSPLUS_VARIANT_SHAKE_A64)
#include "../../sphincsplus/shake-a64/randombytes.h"
#elif defined(SPHINCSPLUS_VARIANT_REF)
#include "../../sphincsplus/ref/randombytes.h"
#else
#error "SPHINCS+ variant not configured"
#endif

/* Forward declaration of our custom implementation from utils.c */
extern void custom_slh_randombytes_impl(uint8_t *out, size_t outlen);

void randombytes(unsigned char *x, unsigned long long xlen)
{
    custom_slh_randombytes_impl((uint8_t*)x, (size_t)xlen);
}
