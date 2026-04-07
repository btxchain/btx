/**
 * @file slh_dsa.h
 * @brief SLH-DSA-Shake-128s (SPHINCS+) specific functions
 */

#ifndef BITCOIN_PQC_SLH_DSA_H
#define BITCOIN_PQC_SLH_DSA_H

#include <stddef.h>
#include <stdint.h>

/* SLH-DSA-Shake-128s constants */
#define SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE 32
#define SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE 64
#define SLH_DSA_SHAKE_128S_SIGNATURE_SIZE 7856

/* Key Generation Functions */

/**
 * @brief Generate an SLH-DSA-Shake-128s key pair
 *
 * @param pk Output public key (must have space for SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE bytes)
 * @param sk Output secret key (must have space for SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE bytes)
 * @param random_data User-provided random data (entropy)
 * @param random_data_size Size of random data, must be >= 128 bytes
 * @return 0 on success, non-zero on failure
 */
int slh_dsa_shake_128s_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Sign a message using SLH-DSA-Shake-128s
 *
 * @param sig Output signature (must have space for SLH_DSA_SHAKE_128S_SIGNATURE_SIZE bytes)
 * @param siglen Output signature length
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 * @return 0 on success, non-zero on failure
 */
int slh_dsa_shake_128s_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
);

/**
 * @brief Sign a message using SLH-DSA-Shake-128s with optional external entropy
 *
 * @param sig Output signature (must have space for SLH_DSA_SHAKE_128S_SIGNATURE_SIZE bytes)
 * @param siglen Output signature length
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 * @param random_data Optional caller-provided entropy for hedged signing
 * @param random_data_size Size of random_data in bytes
 * @return 0 on success, non-zero on failure
 */
int slh_dsa_shake_128s_sign_with_randomness(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Verify an SLH-DSA-Shake-128s signature
 *
 * @param sig Signature
 * @param siglen Signature length
 * @param m Message
 * @param mlen Message length
 * @param pk Public key
 * @return 0 if signature is valid, non-zero otherwise
 */
int slh_dsa_shake_128s_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
);

/**
 * Generates deterministic randomness from a message and secret key
 * @param seed Output buffer for the generated randomness (64 bytes)
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 */
void slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk);

#endif /* BITCOIN_PQC_SLH_DSA_H */
