// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_TEST_UTIL_SMILE2_PLACEHOLDER_UTILS_H
#define BTX_TEST_UTIL_SMILE2_PLACEHOLDER_UTILS_H

#include <crypto/sha256.h>
#include <hash.h>
#include <shielded/account_registry.h>
#include <shielded/smile2/wallet_bridge.h>

#include <cstring>

namespace smile2::wallet {
namespace testonly {

inline uint64_t HashToLegacyKeySeed(const std::array<uint8_t, 32>& hash)
{
    uint64_t seed;
    std::memcpy(&seed, hash.data(), sizeof(seed));
    return seed == 0 ? 1 : seed;
}

inline SmilePublicKey CommitmentToLegacyPublicKey(const std::array<uint8_t, 32>& global_seed,
                                                  const uint256& commitment)
{
    CSHA256 hasher;
    static constexpr const char* domain = "BTX-SMILE-V2-COMMITMENT-TO-PK";
    hasher.Write(reinterpret_cast<const uint8_t*>(domain), std::strlen(domain));
    hasher.Write(commitment.begin(), 32);
    std::array<uint8_t, 32> pk_seed{};
    hasher.Finalize(pk_seed.data());
    return SmileKeyPair::Generate(global_seed, HashToLegacyKeySeed(pk_seed)).pub;
}

inline SmilePoly CommitmentToLegacyCoinPoly(const uint256& commitment)
{
    SmilePoly coin;
    static constexpr const char* domain = "BTX-SMILE-V2-COMMITMENT-TO-COIN";
    for (size_t block = 0; block < POLY_DEGREE; block += 8) {
        CSHA256 hasher;
        hasher.Write(reinterpret_cast<const uint8_t*>(domain), std::strlen(domain));
        hasher.Write(commitment.begin(), commitment.size());
        const uint32_t blk = static_cast<uint32_t>(block);
        hasher.Write(reinterpret_cast<const uint8_t*>(&blk), sizeof(blk));

        uint8_t hash[32];
        hasher.Finalize(hash);
        for (size_t i = 0; i < 8 && (block + i) < POLY_DEGREE; ++i) {
            uint32_t val;
            std::memcpy(&val, hash + 4 * i, sizeof(val));
            coin.coeffs[block + i] = static_cast<int64_t>(val % Q);
        }
    }
    return coin;
}

inline uint256 DerivePlaceholderCoinSeed(const uint256& note_commitment, uint32_t row)
{
    HashWriter hw;
    hw << std::string{"BTX-SMILE-V2-PLACEHOLDER-COIN-V1"} << note_commitment << row;
    return hw.GetSHA256();
}

} // namespace testonly

inline SmileKeyPair DeriveSmileKeyPair(const std::array<uint8_t, 32>& global_seed,
                                       const uint256& note_commitment)
{
    CSHA256 hasher;
    static constexpr const char* domain = "BTX-SMILE-V2-COMMITMENT-TO-PK";
    hasher.Write(reinterpret_cast<const uint8_t*>(domain), std::strlen(domain));
    hasher.Write(note_commitment.begin(), 32);
    std::array<uint8_t, 32> pk_seed{};
    hasher.Finalize(pk_seed.data());
    return SmileKeyPair::Generate(global_seed, testonly::HashToLegacyKeySeed(pk_seed));
}

inline SmileRingMember BuildPlaceholderRingMember(const std::array<uint8_t, 32>& global_seed,
                                                  const uint256& note_commitment)
{
    SmileRingMember member;
    member.note_commitment = note_commitment;
    member.public_key = testonly::CommitmentToLegacyPublicKey(global_seed, note_commitment);
    member.public_coin.t0.assign(BDLOP_RAND_DIM_BASE, {});
    for (size_t row = 0; row < member.public_coin.t0.size(); ++row) {
        member.public_coin.t0[row] = testonly::CommitmentToLegacyCoinPoly(
            testonly::DerivePlaceholderCoinSeed(note_commitment, static_cast<uint32_t>(row)));
    }
    member.public_coin.t_msg = {testonly::CommitmentToLegacyCoinPoly(note_commitment)};
    CompactPublicAccount account;
    account.public_key = member.public_key.pk;
    account.public_coin = member.public_coin;
    const auto account_leaf = shielded::registry::BuildShieldedAccountLeaf(
        account,
        note_commitment,
        shielded::registry::AccountDomain::DIRECT_SEND);
    if (account_leaf.has_value()) {
        member.account_leaf_commitment = shielded::registry::ComputeShieldedAccountLeafCommitment(*account_leaf);
    }
    return member;
}

} // namespace smile2::wallet

#endif // BTX_TEST_UTIL_SMILE2_PLACEHOLDER_UTILS_H
