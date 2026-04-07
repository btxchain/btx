// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// PQ signature key derivation is provided by pq/pq_keyderivation.cpp via
// inline wrappers in the header.  This file implements ML-KEM key derivation
// for the wallet namespace (DeriveMLKEMSeedFromBIP39, DeriveMLKEMKeyFromBIP39).
#include <wallet/pq_keyderivation.h>

#include <crypto/common.h>
#include <crypto/hkdf_sha256_32.h>
#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <string>

namespace {

constexpr uint32_t BIP32_HARDENED_FLAG = 0x80000000U;
constexpr const char* MLKEM_DERIVATION_SALT = "BTX-MLKEM-BIP88-HKDF-V1";
constexpr const char* MLKEM_DERIVATION_INFO_TAG = "m/88h";
constexpr uint8_t MLKEM_ALGORITHM_BYTE = 0x02;

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

namespace wallet {

std::array<unsigned char, mlkem::KEYGEN_SEEDBYTES> DeriveMLKEMSeedFromBIP39(
    Span<const unsigned char> master_seed,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index)
{
    std::array<unsigned char, mlkem::KEYGEN_SEEDBYTES> seed{};
    if (master_seed.empty()) return seed;

    CHKDF_HMAC_SHA256_L32 hkdf(master_seed.data(), master_seed.size(), MLKEM_DERIVATION_SALT);
    std::string info{MLKEM_DERIVATION_INFO_TAG};
    info.reserve(info.size() + (5 * sizeof(uint32_t)) + sizeof(uint8_t));
    AppendBE32(info, 88U | BIP32_HARDENED_FLAG);
    AppendBE32(info, coin_type | BIP32_HARDENED_FLAG);
    AppendBE32(info, account | BIP32_HARDENED_FLAG);
    AppendBE32(info, change);
    AppendBE32(info, index);
    info.push_back(static_cast<char>(MLKEM_ALGORITHM_BYTE));

    std::string left_info{info};
    left_info.push_back('/');
    left_info.push_back('0');
    std::string right_info{info};
    right_info.push_back('/');
    right_info.push_back('1');

    std::array<unsigned char, 32> left{};
    std::array<unsigned char, 32> right{};
    hkdf.Expand32(left_info, left.data());
    hkdf.Expand32(right_info, right.data());
    std::copy(left.begin(), left.end(), seed.begin());
    std::copy(right.begin(), right.end(), seed.begin() + 32);
    CleanseString(left_info);
    CleanseString(right_info);
    CleanseString(info);
    memory_cleanse(left.data(), left.size());
    memory_cleanse(right.data(), right.size());
    return seed;
}

mlkem::KeyPair DeriveMLKEMKeyFromBIP39(
    Span<const unsigned char> master_seed,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index)
{
    auto seed = DeriveMLKEMSeedFromBIP39(master_seed, coin_type, account, change, index);
    if (master_seed.empty()) return mlkem::KeyPair{};
    mlkem::KeyPair kp = mlkem::KeyGenDerand(seed);
    memory_cleanse(seed.data(), seed.size());
    return kp;
}

} // namespace wallet
