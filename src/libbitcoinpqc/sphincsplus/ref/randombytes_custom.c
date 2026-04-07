#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"

/* Forward declaration of our custom implementation from utils.c */
extern void custom_slh_randombytes_impl(uint8_t *out, size_t outlen);

/* This function is the original randombytes implementation but calls our custom implementation */
void randombytes(unsigned char *x, unsigned long long xlen) {
    custom_slh_randombytes_impl(x, (size_t)xlen);
}
