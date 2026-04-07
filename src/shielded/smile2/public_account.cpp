// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/public_account.h>
#include <shielded/smile2/domain_separation.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <streams.h>

#include <cstring>
#include <string_view>

namespace smile2 {
namespace {

constexpr std::string_view TAG_COMPACT_PUBLIC_ACCOUNT{"BTX_SMILE2_Compact_Public_Account_V1"};
constexpr std::string_view TAG_COMPACT_PUBLIC_KEY_SLOT_KEY{"BTX_SMILE2_Compact_Public_Key_Slot_Key_V1"};
constexpr uint8_t PUBLIC_COIN_KEY_SEED_BYTE{0xCC};

SmilePoly HashToPoly(const uint8_t* data, size_t len, uint32_t domain, uint32_t index)
{
    SmilePoly poly;
    for (size_t block = 0; block < POLY_DEGREE; block += 8) {
        CSHA256 hasher;
        hasher.Write(data, len);
        uint8_t buffer[12];
        WriteLE32(buffer, domain);
        WriteLE32(buffer + 4, index);
        const uint32_t block_index = static_cast<uint32_t>(block);
        WriteLE32(buffer + 8, block_index);
        hasher.Write(buffer, sizeof(buffer));
        uint8_t hash[32];
        hasher.Finalize(hash);
        for (size_t i = 0; i < 8 && (block + i) < POLY_DEGREE; ++i) {
            const uint32_t value = ReadLE32(hash + 4 * i);
            poly.coeffs[block + i] = static_cast<int64_t>(value % Q);
        }
    }
    return poly;
}

std::vector<std::vector<SmilePoly>> BuildGlobalMatrix(const std::array<uint8_t, 32>& seed)
{
    std::vector<std::vector<SmilePoly>> matrix(KEY_ROWS, std::vector<SmilePoly>(KEY_COLS));
    for (size_t row = 0; row < KEY_ROWS; ++row) {
        for (size_t col = 0; col < KEY_COLS; ++col) {
            matrix[row][col] = HashToPoly(seed.data(),
                                          seed.size(),
                                          domainsep::PUBLIC_ACCOUNT_MATRIX,
                                          static_cast<uint32_t>(row * KEY_COLS + col));
        }
    }
    return matrix;
}

std::array<uint8_t, 32> BuildTaggedSeed(std::string_view tag)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(tag.data()), tag.size());
    std::array<uint8_t, 32> seed{};
    hasher.Finalize(seed.data());
    return seed;
}

BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> seed{};
    seed[0] = PUBLIC_COIN_KEY_SEED_BYTE;
    return BDLOPCommitmentKey::Generate(seed, 1);
}

} // namespace

bool CompactPublicAccount::IsValid() const
{
    return version == WIRE_VERSION &&
           public_key.size() == KEY_ROWS &&
           public_coin.t0.size() == BDLOP_RAND_DIM_BASE &&
           public_coin.t_msg.size() == 1;
}

bool CompactPublicKeyData::IsValid() const
{
    return public_key.size() == KEY_ROWS;
}

SmilePublicKey ExpandCompactPublicKey(Span<const SmilePoly> public_key_rows,
                                      const std::array<uint8_t, 32>& matrix_seed)
{
    SmilePublicKey public_key;
    public_key.A = BuildGlobalMatrix(matrix_seed);
    public_key.pk.assign(public_key_rows.begin(), public_key_rows.end());
    return public_key;
}

SmilePublicKey ExpandCompactPublicKey(const CompactPublicAccount& account,
                                      const std::array<uint8_t, 32>& matrix_seed)
{
    return ExpandCompactPublicKey(Span<const SmilePoly>{account.public_key.data(), account.public_key.size()},
                                  matrix_seed);
}

std::vector<uint8_t> SerializeCompactPublicAccount(const CompactPublicAccount& account)
{
    DataStream ds;
    ::Serialize(ds, account);
    if (ds.empty()) return {};
    const auto* begin = reinterpret_cast<const uint8_t*>(ds.data());
    return {begin, begin + ds.size()};
}

std::optional<CompactPublicAccount> DeserializeCompactPublicAccount(Span<const uint8_t> bytes)
{
    DataStream ds{std::vector<uint8_t>{bytes.begin(), bytes.end()}};
    CompactPublicAccount account;
    try {
        ::Unserialize(ds, account);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!ds.empty() || !account.IsValid()) return std::nullopt;
    return account;
}

uint256 ComputeCompactPublicAccountHash(const CompactPublicAccount& account)
{
    HashWriter hw;
    hw << std::string{TAG_COMPACT_PUBLIC_ACCOUNT} << account;
    return hw.GetSHA256();
}

CompactPublicKeyData ExtractCompactPublicKeyData(const CompactPublicAccount& account)
{
    CompactPublicKeyData key_data;
    key_data.public_key = account.public_key;
    return key_data;
}

std::optional<CompactPublicAccount> BuildCompactPublicAccountFromPublicParts(
    Span<const SmilePoly> public_key_rows,
    const BDLOPCommitment& public_coin)
{
    if (public_key_rows.size() != KEY_ROWS ||
        public_coin.t0.size() != BDLOP_RAND_DIM_BASE ||
        public_coin.t_msg.size() != 1) {
        return std::nullopt;
    }

    CompactPublicAccount account;
    account.public_key.assign(public_key_rows.begin(), public_key_rows.end());
    account.public_coin = public_coin;
    if (!account.IsValid()) {
        return std::nullopt;
    }
    return account;
}

std::optional<CompactPublicAccount> BuildCompactPublicAccountFromPublicParts(
    const CompactPublicKeyData& public_key,
    const BDLOPCommitment& public_coin)
{
    if (!public_key.IsValid()) {
        return std::nullopt;
    }
    return BuildCompactPublicAccountFromPublicParts(
        Span<const SmilePoly>{public_key.public_key.data(), public_key.public_key.size()},
        public_coin);
}

BDLOPCommitmentKey GetCompactPublicKeySlotCommitmentKey()
{
    static const BDLOPCommitmentKey slot_ck = []() {
        const auto seed = BuildTaggedSeed(TAG_COMPACT_PUBLIC_KEY_SLOT_KEY);
        BDLOPCommitmentKey ck = BDLOPCommitmentKey::Generate(seed, KEY_ROWS);
        const BDLOPCommitmentKey coin_ck = GetPublicCoinCommitmentKey();

        // Reuse the live coin-commitment B0 surface for the shared opening
        // dimensions so key slots and public coins can be authenticated by the
        // same witness. The additional KEY_ROWS tail coordinates are zeroed and
        // therefore do not affect the coin-opening rows.
        for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
            for (size_t col = 0; col < ck.rand_dim(); ++col) {
                ck.B0[row][col] = SmilePoly{};
            }
            for (size_t col = 0; col < coin_ck.rand_dim(); ++col) {
                ck.B0[row][col] = coin_ck.B0[row][col];
            }
        }

        ck.RebuildNttCache();

        return ck;
    }();
    return slot_ck;
}

SmilePolyVec ExtendCompactPublicKeySlotOpening(Span<const SmilePoly> coin_opening)
{
    const auto slot_ck = GetCompactPublicKeySlotCommitmentKey();
    if (coin_opening.size() != BDLOP_RAND_DIM_BASE + 1) {
        return {};
    }

    SmilePolyVec opening(slot_ck.rand_dim());
    for (size_t i = 0; i < coin_opening.size(); ++i) {
        opening[i] = coin_opening[i];
    }
    return opening;
}

SmilePolyVec ComputeCompactPublicKeySlots(Span<const SmilePoly> public_key_rows,
                                          Span<const SmilePoly> coin_opening)
{
    if (public_key_rows.size() != KEY_ROWS || coin_opening.size() != BDLOP_RAND_DIM_BASE + 1) {
        return {};
    }

    const auto slot_ck = GetCompactPublicKeySlotCommitmentKey();
    const SmilePolyVec slot_opening = ExtendCompactPublicKeySlotOpening(coin_opening);
    if (slot_opening.size() != slot_ck.rand_dim()) {
        return {};
    }

    SmilePolyVec slots(KEY_ROWS);
    std::vector<NttForm> slot_opening_ntt(slot_opening.size());
    for (size_t col = 0; col < slot_opening.size(); ++col) {
        slot_opening_ntt[col] = NttForward(slot_opening[col]);
    }
    for (size_t row = 0; row < KEY_ROWS; ++row) {
        SmilePoly slot = public_key_rows[row];
        NttForm slot_acc_ntt;
        for (size_t col = 0; col < slot_ck.rand_dim(); ++col) {
            slot_acc_ntt += slot_ck.b_ntt[row][col].PointwiseMul(slot_opening_ntt[col]);
        }
        slot += NttInverse(slot_acc_ntt);
        slot.Reduce();
        slots[row] = std::move(slot);
    }
    return slots;
}

SmilePolyVec ComputeCompactPublicKeySlots(const CompactPublicAccount& account,
                                          Span<const SmilePoly> coin_opening)
{
    return ComputeCompactPublicKeySlots(
        Span<const SmilePoly>{account.public_key.data(), account.public_key.size()},
        coin_opening);
}

} // namespace smile2
