// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/ml_kem.h>

#include <random.h>
#include <support/cleanse.h>
#include <util/check.h>

#include <algorithm>

extern "C" {
#include <crypto/ml-kem-768/kem.h>
}

namespace {
void FillRandomBytes(uint8_t* out, size_t n, bool strong) noexcept
{
    while (n > 0) {
        const size_t chunk = std::min<size_t>(n, 32);
        if (strong) {
            GetStrongRandBytes(Span<unsigned char>(out, chunk));
        } else {
            GetRandBytes(Span<unsigned char>(out, chunk));
        }
        out += chunk;
        n -= chunk;
    }
}
} // namespace

extern "C" int PQCLEAN_randombytes(uint8_t* output, size_t n)
{
    FillRandomBytes(output, n, /*strong=*/true);
    return 0;
}

namespace mlkem {

KeyPair KeyGen()
{
    std::array<uint8_t, KEYGEN_SEEDBYTES> seed;
    FillRandomBytes(seed.data(), seed.size(), /*strong=*/true);
    KeyPair result = KeyGenDerand(seed);
    memory_cleanse(seed.data(), seed.size());
    return result;
}

KeyPair KeyGenDerand(Span<const uint8_t> seed)
{
    Assume(seed.size() == KEYGEN_SEEDBYTES);
    KeyPair result;
    const int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(
        result.pk.data(), result.sk.data(), seed.data());
    Assume(rc == 0);
    return result;
}

EncapsResult Encaps(const PublicKey& pk)
{
    std::array<uint8_t, ENCAPS_SEEDBYTES> coin;
    FillRandomBytes(coin.data(), coin.size(), /*strong=*/true);
    EncapsResult result = EncapsDerand(pk, coin);
    memory_cleanse(coin.data(), coin.size());
    return result;
}

EncapsResult EncapsDerand(const PublicKey& pk, Span<const uint8_t> seed)
{
    Assume(seed.size() == ENCAPS_SEEDBYTES);
    EncapsResult result;
    const int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
        result.ct.data(), result.ss.data(), pk.data(), seed.data());
    Assume(rc == 0);
    return result;
}

SharedSecret Decaps(const Ciphertext& ct, const SecretKey& sk)
{
    Assume(sk.size() == SECRETKEYBYTES);
    SharedSecret ss(SHAREDSECRETBYTES, 0);
    const int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
        ss.data(), ct.data(), sk.data());
    Assume(rc == 0);
    return ss;
}

} // namespace mlkem
