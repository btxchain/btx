/**
 * @file ml_dsa.h
 * @brief ML-DSA-44 (CRYSTALS-Dilithium) specific functions
 */

#ifndef BITCOIN_PQC_ML_DSA_H
#define BITCOIN_PQC_ML_DSA_H

#include <stddef.h>
#include <stdint.h>

/* ML-DSA-44 constants */
#define ML_DSA_44_PUBLIC_KEY_SIZE 1312
#define ML_DSA_44_SECRET_KEY_SIZE 2560
#define ML_DSA_44_SIGNATURE_SIZE 2420

/* Key Generation Functions */

/**
 * @brief Generate an ML-DSA-44 key pair
 *
 * @param pk Output public key (must have space for ML_DSA_44_PUBLIC_KEY_SIZE bytes)
 * @param sk Output secret key (must have space for ML_DSA_44_SECRET_KEY_SIZE bytes)
 * @param random_data User-provided random data (entropy)
 * @param random_data_size Size of random data, must be >= 128 bytes
 * @return 0 on success, non-zero on failure
 */
int ml_dsa_44_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/* Signing Functions */

/**
 * @brief Sign a message using ML-DSA-44
 *
 * @param sig Output signature (must have space for ML_DSA_44_SIGNATURE_SIZE bytes)
 * @param siglen Output signature length
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 * @return 0 on success, non-zero on failure
 */
int ml_dsa_44_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
);

/**
 * @brief Sign a message using ML-DSA-44 with optional external entropy
 *
 * @param sig Output signature (must have space for ML_DSA_44_SIGNATURE_SIZE bytes)
 * @param siglen Output signature length
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 * @param random_data Optional caller-provided entropy for hedged signing
 * @param random_data_size Size of random_data in bytes
 * @return 0 on success, non-zero on failure
 */
int ml_dsa_44_sign_with_randomness(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/* Verification Functions */

/**
 * @brief Verify an ML-DSA-44 signature
 *
 * @param sig Signature
 * @param siglen Signature length
 * @param m Message
 * @param mlen Message length
 * @param pk Public key
 * @return 0 if signature is valid, non-zero otherwise
 */
int ml_dsa_44_verify(
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
void ml_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk);

#endif /* BITCOIN_PQC_ML_DSA_H */
