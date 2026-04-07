// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_UTIL_SHIELDED_SMILE_TEST_UTIL_H
#define BTX_TEST_UTIL_SHIELDED_SMILE_TEST_UTIL_H

#include <consensus/amount.h>
#include <shielded/note.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/wallet_bridge.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace test::shielded {

inline uint256 MakeDeterministicTestUint256(uint32_t seed, unsigned char domain)
{
    uint256 value;
    value.SetNull();
    for (size_t i = 0; i < sizeof(seed); ++i) {
        value.begin()[i] = static_cast<unsigned char>((seed >> (8 * i)) & 0xff);
    }
    value.begin()[sizeof(seed)] = domain;
    value.begin()[sizeof(seed) + 1] = static_cast<unsigned char>(domain ^ 0x5a);
    return value;
}

inline ShieldedNote MakeDeterministicSmileNote(uint32_t seed, CAmount value = 0)
{
    ShieldedNote note;
    note.value = value > 0 ? value : static_cast<CAmount>((seed % 100000U) + 1U);
    note.recipient_pk_hash = MakeDeterministicTestUint256(seed, 0x11);
    note.rho = MakeDeterministicTestUint256(seed ^ 0x9e3779b9U, 0x22);
    note.rcm = MakeDeterministicTestUint256(seed ^ 0x85ebca6bU, 0x33);
    if (!note.IsValid()) {
        throw std::runtime_error("invalid deterministic shielded SMILE note fixture");
    }
    return note;
}

inline smile2::CompactPublicAccount MakeDeterministicCompactPublicAccount(uint32_t seed,
                                                                          CAmount value = 0)
{
    const ShieldedNote note = MakeDeterministicSmileNote(seed, value);
    auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    if (!account.has_value()) {
        throw std::runtime_error("failed to build deterministic shielded SMILE account fixture");
    }
    return *account;
}

inline std::vector<std::vector<smile2::CTPublicAccount>> BuildDeterministicCTAccountRings(
    const std::vector<smile2::SmileKeyPair>& keys,
    const std::vector<std::vector<smile2::BDLOPCommitment>>& coin_rings,
    uint32_t note_seed_base,
    unsigned char domain)
{
    std::vector<uint256> note_commitments;
    note_commitments.reserve(keys.size());
    for (size_t member = 0; member < keys.size(); ++member) {
        note_commitments.push_back(MakeDeterministicTestUint256(
            note_seed_base + static_cast<uint32_t>(member),
            domain));
    }

    std::vector<std::vector<smile2::CTPublicAccount>> account_rings;
    account_rings.reserve(coin_rings.size());
    for (const auto& ring_coins : coin_rings) {
        if (ring_coins.size() != keys.size()) {
            throw std::runtime_error("coin ring size does not match deterministic CT account ring key count");
        }
        std::vector<smile2::CTPublicAccount> ring;
        ring.reserve(keys.size());
        for (size_t member = 0; member < keys.size(); ++member) {
            ring.push_back(smile2::CTPublicAccount{
                note_commitments[member],
                keys[member].pub,
                ring_coins[member],
                MakeDeterministicTestUint256(
                    note_seed_base + static_cast<uint32_t>(member),
                    static_cast<unsigned char>(domain ^ 0x6d)),
            });
        }
        account_rings.push_back(std::move(ring));
    }

    return account_rings;
}

} // namespace test::shielded

#endif // BTX_TEST_UTIL_SHIELDED_SMILE_TEST_UTIL_H
