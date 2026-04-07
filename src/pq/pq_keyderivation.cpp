// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <pq/pq_keyderivation.h>

#include <crypto/common.h>
#include <crypto/hkdf_sha256_32.h>
#include <support/cleanse.h>

#include <array>
#include <string>

namespace pq {
namespace {

constexpr uint32_t BIP32_HARDENED_FLAG = 0x80000000U;
constexpr const char* PQ_DERIVATION_SALT = "BTX-PQ-BIP87-HKDF-V1";
constexpr const char* PQ_DERIVATION_INFO_TAG = "m/87h";

void AppendBE32(std::string& out, uint32_t value)
{
    std::array<unsigned char, 4> data{};
    WriteBE32(data.data(), value);
    out.append(reinterpret_cast<const char*>(data.data()), data.size());
}

void CleanseString(std::string& value)
{
    if (value.empty()) return;
    memory_cleanse(value.data(), value.size());
    value.clear();
}

} // namespace

std::array<unsigned char, 32> DerivePQSeedFromBIP39(
    Span<const unsigned char> master_seed,
    PQAlgorithm algo,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index)
{
    std::array<unsigned char, 32> seed{};
    if (master_seed.empty()) return seed;

    CHKDF_HMAC_SHA256_L32 hkdf(master_seed.data(), master_seed.size(), PQ_DERIVATION_SALT);
    std::string info{PQ_DERIVATION_INFO_TAG};
    info.reserve(info.size() + (5 * sizeof(uint32_t)) + sizeof(uint8_t));

    AppendBE32(info, 87U | BIP32_HARDENED_FLAG);
    AppendBE32(info, coin_type | BIP32_HARDENED_FLAG);
    AppendBE32(info, account | BIP32_HARDENED_FLAG);
    AppendBE32(info, change);
    AppendBE32(info, index);
    info.push_back(static_cast<char>(algo));

    hkdf.Expand32(info, seed.data());
    CleanseString(info);
    return seed;
}

std::optional<CPQKey> DerivePQKeyFromBIP39(
    Span<const unsigned char> master_seed,
    PQAlgorithm algo,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index)
{
    if (master_seed.empty()) return std::nullopt;

    std::array<unsigned char, 32> seed{
        DerivePQSeedFromBIP39(master_seed, algo, coin_type, account, change, index)};

    CPQKey key;
    const bool derived = key.MakeDeterministicKey(algo, seed);
    memory_cleanse(seed.data(), seed.size());
    if (!derived) return std::nullopt;
    return key;
}

} // namespace pq
