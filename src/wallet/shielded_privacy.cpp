// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/shielded_privacy.h>

#include <chainparams.h>
#include <common/args.h>
#include <hash.h>
#include <random.h>
#include <shielded/ringct/ring_selection.h>
#include <shielded/v2_send.h>
#include <util/strencodings.h>
#include <wallet/shielded_coins.h>

#include <algorithm>
#include <numeric>
#include <set>

namespace wallet {
namespace {

static constexpr uint64_t LEGACY_SHIELDED_DECOY_TIP_EXCLUSION_WINDOW{100};
static constexpr size_t SHIELDED_HISTORICAL_RING_EXCLUSION_WINDOWS{16};
static constexpr size_t SHIELDED_HISTORICAL_RING_EXCLUSION_MIN{64};
static constexpr const char* POSTFORK_COINBASE_SHIELDING_COMPATIBILITY_MESSAGE{
    "post-fork direct transparent shielding is limited to mature coinbase outputs; "
    "use bridge ingress for general transparent deposits"};

[[nodiscard]] int32_t GetShieldedPrivacyRedesignActivationHeight()
{
    int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
    if (gArgs.GetChainType() == ChainType::REGTEST &&
        gArgs.IsArgSet("-regtestshieldedmatrictdisableheight")) {
        int32_t override_height{0};
        const auto raw_override = gArgs.GetArg("-regtestshieldedmatrictdisableheight", "");
        if (ParseInt32(raw_override, &override_height) && override_height >= 0) {
            activation_height = override_height;
        }
    }
    return activation_height;
}

} // namespace

bool UseShieldedPrivacyRedesignAtHeight(int32_t height)
{
    return height >= GetShieldedPrivacyRedesignActivationHeight();
}

bool RedactSensitiveShieldedRpcFieldsAtHeight(int32_t height, bool include_sensitive)
{
    return UseShieldedPrivacyRedesignAtHeight(height) && !include_sensitive;
}

bool RequireSensitiveShieldedRpcOptInAtHeight(int32_t height)
{
    return UseShieldedPrivacyRedesignAtHeight(height);
}

bool AllowMixedTransparentShieldedSendAtHeight(int32_t height)
{
    return !UseShieldedPrivacyRedesignAtHeight(height);
}

bool AllowTransparentShieldingInDirectSendAtHeight(int32_t height)
{
    return !UseShieldedPrivacyRedesignAtHeight(height);
}

const char* GetPostForkCoinbaseShieldingCompatibilityMessage()
{
    return POSTFORK_COINBASE_SHIELDING_COMPATIBILITY_MESSAGE;
}

uint64_t GetShieldedDecoyTipExclusionWindowForHeight(int32_t height)
{
    return UseShieldedPrivacyRedesignAtHeight(height) ? 0 : LEGACY_SHIELDED_DECOY_TIP_EXCLUSION_WINDOW;
}

CAmount GetShieldedDustThresholdForHeight(const CFeeRate& relay_dust_fee, int32_t height)
{
    if (!UseShieldedPrivacyRedesignAtHeight(height)) {
        return 0;
    }
    const size_t spend_and_output_bytes =
        SHIELDED_SPEND_INPUT_SIZE + SHIELDED_OUTPUT_SIZE;
    return std::max<CAmount>(1, relay_dust_fee.GetFee(spend_and_output_bytes));
}

CAmount GetShieldedMinimumChangeReserveForHeight(const CFeeRate& relay_dust_fee, int32_t height)
{
    return std::max<CAmount>(1, GetShieldedDustThresholdForHeight(relay_dust_fee, height));
}

bool PreferExactBalanceShieldedChangeReserve(CAmount change,
                                             size_t selected_note_count,
                                             size_t shielded_recipient_count,
                                             size_t transparent_recipient_count)
{
    return change == 0 &&
           selected_note_count > 1 &&
           shielded_recipient_count == 1 &&
           transparent_recipient_count == 0;
}

bool SelectionFitsDirectShieldedSpendLimits(size_t selected_note_count, size_t ring_size)
{
    return selected_note_count <= shielded::v2::MAX_DIRECT_SPENDS &&
           selected_note_count <= shielded::v2::MAX_LIVE_DIRECT_SMILE_SPENDS &&
           selected_note_count <= ring_size;
}

uint64_t GetShieldedMinimumPrivacyTreeSizeForHeight(size_t ring_size, int32_t height)
{
    if (!UseShieldedPrivacyRedesignAtHeight(height)) {
        return 0;
    }
    return shielded::ringct::GetMinimumPrivacyTreeSize(ring_size);
}

size_t GetShieldedHistoricalRingExclusionLimit(size_t ring_size, int32_t height)
{
    if (!UseShieldedPrivacyRedesignAtHeight(height) || ring_size <= 1) {
        return 0;
    }
    const size_t decoy_count = ring_size - 1;
    return std::max(SHIELDED_HISTORICAL_RING_EXCLUSION_MIN,
                    decoy_count * SHIELDED_HISTORICAL_RING_EXCLUSION_WINDOWS);
}

std::vector<uint64_t> BuildShieldedHistoricalRingExclusions(Span<const uint64_t> tip_exclusions,
                                                            Span<const uint64_t> historical_exclusions,
                                                            uint64_t tree_size)
{
    std::vector<uint64_t> merged;
    merged.reserve(tip_exclusions.size() + historical_exclusions.size());
    std::set<uint64_t> seen;

    const auto append = [&](Span<const uint64_t> positions) {
        for (const uint64_t pos : positions) {
            if (pos >= tree_size) continue;
            if (seen.insert(pos).second) {
                merged.push_back(pos);
            }
        }
    };

    append(tip_exclusions);
    append(historical_exclusions);
    return merged;
}

void UpdateShieldedHistoricalRingExclusionCache(std::vector<uint64_t>& cache,
                                                Span<const uint64_t> ring_positions,
                                                Span<const size_t> real_indices,
                                                size_t limit)
{
    if (limit == 0) {
        cache.clear();
        return;
    }

    std::set<size_t> real_index_set(real_indices.begin(), real_indices.end());
    for (size_t i = 0; i < ring_positions.size(); ++i) {
        if (real_index_set.count(i) != 0) continue;
        const uint64_t pos = ring_positions[i];
        const auto existing = std::find(cache.begin(), cache.end(), pos);
        if (existing != cache.end()) {
            cache.erase(existing);
        }
        cache.push_back(pos);
    }

    if (cache.size() > limit) {
        cache.erase(cache.begin(), cache.end() - static_cast<std::ptrdiff_t>(limit));
    }
}

uint256 DeriveShieldedSharedRingSeed(Span<const Nullifier> nullifiers,
                                     Span<const unsigned char> spend_key_material,
                                     const uint256& build_nonce,
                                     int32_t height)
{
    HashWriter hw;
    hw << std::string{UseShieldedPrivacyRedesignAtHeight(height)
                          ? "BTX_Shielded_SMILE_SharedRing_V2"
                          : "BTX_Shielded_SMILE_SharedRing_V1"};
    for (const auto& nullifier : nullifiers) {
        hw << nullifier;
    }
    if (UseShieldedPrivacyRedesignAtHeight(height)) {
        hw << build_nonce;
    }
    hw << spend_key_material;
    return hw.GetSHA256();
}

std::vector<size_t> ComputeShieldedOutputOrder(size_t recipient_count,
                                               bool has_change,
                                               const uint256& build_nonce,
                                               int32_t height)
{
    std::vector<size_t> order(recipient_count + (has_change ? 1 : 0));
    std::iota(order.begin(), order.end(), 0);
    if (!UseShieldedPrivacyRedesignAtHeight(height) || order.size() < 2) {
        return order;
    }

    std::shuffle(order.begin(), order.end(), FastRandomContext(build_nonce));
    return order;
}

} // namespace wallet
