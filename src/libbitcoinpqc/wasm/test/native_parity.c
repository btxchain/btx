/*
 * Deterministic keygen vectors from the NATIVE libbitcoinpqc build, printed
 * in the exact format emitted by print-wasm-vectors.mjs so CI can `diff`
 * native vs WASM output. The fixed entropy pattern must stay in sync with
 * test/pqc.mjs fixedEntropy().
 */

#include <libbitcoinpqc/bitcoinpqc.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main(void)
{
    uint8_t entropy[128];
    for (int i = 0; i < 128; i++) entropy[i] = (uint8_t)((i * 7 + 13) & 0xff);

    bitcoin_pqc_keypair_t kp;

    memset(&kp, 0, sizeof(kp));
    if (bitcoin_pqc_keygen(BITCOIN_PQC_ML_DSA_44, &kp, entropy, sizeof(entropy)) != BITCOIN_PQC_OK) {
        fprintf(stderr, "ML-DSA keygen failed\n");
        return 1;
    }
    print_hex("ML-DSA pk[0:16]: ", (const uint8_t *)kp.public_key, 16);
    bitcoin_pqc_keypair_free(&kp);

    memset(&kp, 0, sizeof(kp));
    if (bitcoin_pqc_keygen(BITCOIN_PQC_SLH_DSA_SHAKE_128S, &kp, entropy, sizeof(entropy)) != BITCOIN_PQC_OK) {
        fprintf(stderr, "SLH-DSA keygen failed\n");
        return 1;
    }
    print_hex("SLH-DSA pk: ", (const uint8_t *)kp.public_key, kp.public_key_size);
    bitcoin_pqc_keypair_free(&kp);

    return 0;
}
