// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_ML_KEM_H
#define BITCOIN_CRYPTO_ML_KEM_H

#include <span.h>
#include <support/allocators/secure.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace mlkem {

static constexpr size_t PUBLICKEYBYTES{1184};
static constexpr size_t SECRETKEYBYTES{2400};
static constexpr size_t CIPHERTEXTBYTES{1088};
static constexpr size_t SHAREDSECRETBYTES{32};
static constexpr size_t KEYGEN_SEEDBYTES{64};
static constexpr size_t ENCAPS_SEEDBYTES{32};

using PublicKey = std::array<uint8_t, PUBLICKEYBYTES>;
using SecretKey = std::vector<uint8_t, secure_allocator<uint8_t>>;
using Ciphertext = std::array<uint8_t, CIPHERTEXTBYTES>;
using SharedSecret = std::vector<uint8_t, secure_allocator<uint8_t>>;

struct KeyPair {
    PublicKey pk{};
    SecretKey sk;
    KeyPair() : sk(SECRETKEYBYTES, 0) {}
};

struct EncapsResult {
    Ciphertext ct{};
    SharedSecret ss;
    EncapsResult() : ss(SHAREDSECRETBYTES, 0) {}
};

/** Generate ML-KEM-768 key pair (system randomness). */
[[nodiscard]] KeyPair KeyGen();

/** Deterministic key generation from a 64-byte seed (tests only). */
[[nodiscard]] KeyPair KeyGenDerand(Span<const uint8_t> seed);

/** Encapsulate to recipient public key. */
[[nodiscard]] EncapsResult Encaps(const PublicKey& pk);

/** Deterministic encapsulation from a 32-byte seed (tests only). */
[[nodiscard]] EncapsResult EncapsDerand(const PublicKey& pk, Span<const uint8_t> seed);

/** Decapsulate: recover shared secret from ciphertext and secret key. */
[[nodiscard]] SharedSecret Decaps(const Ciphertext& ct, const SecretKey& sk);

} // namespace mlkem

#endif // BITCOIN_CRYPTO_ML_KEM_H
