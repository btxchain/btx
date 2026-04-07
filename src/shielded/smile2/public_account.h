// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_PUBLIC_ACCOUNT_H
#define BTX_SHIELDED_SMILE2_PUBLIC_ACCOUNT_H

#include <serialize.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <ios>
#include <optional>
#include <vector>

namespace smile2 {

template <typename Stream>
void SerializeCompactPublicCoin(Stream& s, const BDLOPCommitment& public_coin)
{
    if (public_coin.t0.size() != BDLOP_RAND_DIM_BASE || public_coin.t_msg.size() != 1) {
        throw std::ios_base::failure("SerializeCompactPublicCoin invalid public_coin shape");
    }
    for (const auto& poly : public_coin.t0) {
        SerializePoly(poly, s);
    }
    for (const auto& poly : public_coin.t_msg) {
        SerializePoly(poly, s);
    }
}

template <typename Stream>
void UnserializeCompactPublicCoin(Stream& s, BDLOPCommitment& public_coin)
{
    public_coin.t0.assign(BDLOP_RAND_DIM_BASE, {});
    for (auto& poly : public_coin.t0) {
        DeserializePoly(s, poly);
    }
    public_coin.t_msg.assign(1, {});
    for (auto& poly : public_coin.t_msg) {
        DeserializePoly(s, poly);
    }
}

/**
 * Compact chain-visible SMILE account data for one shielded output.
 *
 * The global A matrix is chain-wide and therefore omitted from the wire
 * representation; only the per-output public key rows and public coin data are
 * serialized. The verifier reconstructs the full SmilePublicKey by reattaching
 * the global matrix derived from the well-known SMILE seed.
 */
struct CompactPublicAccount
{
    static constexpr uint8_t WIRE_VERSION{1};

    uint8_t version{WIRE_VERSION};
    SmilePolyVec public_key;
    BDLOPCommitment public_coin;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (version != WIRE_VERSION) {
            throw std::ios_base::failure("CompactPublicAccount::Serialize invalid version");
        }
        if (public_key.size() != KEY_ROWS) {
            throw std::ios_base::failure("CompactPublicAccount::Serialize invalid public_key size");
        }
        for (const auto& row : public_key) {
            SerializePoly(row, s);
        }
        SerializeCompactPublicCoin(s, public_coin);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        version = WIRE_VERSION;
        public_key.assign(KEY_ROWS, {});
        for (auto& row : public_key) {
            DeserializePoly(s, row);
        }
        UnserializeCompactPublicCoin(s, public_coin);
    }
};

struct CompactPublicKeyData
{
    SmilePolyVec public_key;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (public_key.size() != KEY_ROWS) {
            throw std::ios_base::failure("CompactPublicKeyData::Serialize invalid public_key size");
        }
        for (const auto& row : public_key) {
            SerializePoly(row, s);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        public_key.assign(KEY_ROWS, {});
        for (auto& row : public_key) {
            DeserializePoly(s, row);
        }
    }
};

[[nodiscard]] SmilePublicKey ExpandCompactPublicKey(
    Span<const SmilePoly> public_key_rows,
    const std::array<uint8_t, 32>& matrix_seed);

[[nodiscard]] SmilePublicKey ExpandCompactPublicKey(
    const CompactPublicAccount& account,
    const std::array<uint8_t, 32>& matrix_seed);

[[nodiscard]] std::vector<uint8_t> SerializeCompactPublicAccount(const CompactPublicAccount& account);
[[nodiscard]] std::optional<CompactPublicAccount> DeserializeCompactPublicAccount(
    Span<const uint8_t> bytes);
[[nodiscard]] uint256 ComputeCompactPublicAccountHash(const CompactPublicAccount& account);
[[nodiscard]] CompactPublicKeyData ExtractCompactPublicKeyData(const CompactPublicAccount& account);
[[nodiscard]] std::optional<CompactPublicAccount> BuildCompactPublicAccountFromPublicParts(
    Span<const SmilePoly> public_key_rows,
    const BDLOPCommitment& public_coin);
[[nodiscard]] std::optional<CompactPublicAccount> BuildCompactPublicAccountFromPublicParts(
    const CompactPublicKeyData& public_key,
    const BDLOPCommitment& public_coin);
[[nodiscard]] BDLOPCommitmentKey GetCompactPublicKeySlotCommitmentKey();
[[nodiscard]] SmilePolyVec ExtendCompactPublicKeySlotOpening(Span<const SmilePoly> coin_opening);
[[nodiscard]] SmilePolyVec ComputeCompactPublicKeySlots(Span<const SmilePoly> public_key_rows,
                                                        Span<const SmilePoly> coin_opening);
[[nodiscard]] SmilePolyVec ComputeCompactPublicKeySlots(const CompactPublicAccount& account,
                                                        Span<const SmilePoly> coin_opening);

} // namespace smile2

#endif // BTX_SHIELDED_SMILE2_PUBLIC_ACCOUNT_H
