// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/shielded_fees.h>

#include <array>
#include <limits>

namespace wallet {
namespace {

constexpr std::array<CAmount, 8> SHIELDED_AUTO_FEE_BUCKETS{
    5'000,
    10'000,
    20'000,
    40'000,
    80'000,
    160'000,
    320'000,
    640'000,
};

// Runtime reports for the current direct-send builder yield the exact fits:
// 1x2 => 60,218 vB, 2x2 => 70,272 vB, 2x4 => 101,918 vB.
constexpr size_t DIRECT_SEND_BASE_VSIZE{18'518};
constexpr size_t DIRECT_SEND_SPEND_VSIZE{10'054};
constexpr size_t DIRECT_SEND_SHIELDED_OUTPUT_VSIZE{15'823};

} // namespace

CAmount BucketShieldedAutoFee(const CAmount fee)
{
    if (fee <= 0) return fee;

    for (const CAmount bucket : SHIELDED_AUTO_FEE_BUCKETS) {
        if (fee <= bucket) return bucket;
    }

    return fee;
}

size_t EstimateDirectShieldedSendVirtualSize(const size_t spend_count,
                                             const size_t shielded_output_count,
                                             const size_t transparent_output_bytes)
{
    if (spend_count > (std::numeric_limits<size_t>::max() - DIRECT_SEND_BASE_VSIZE) / DIRECT_SEND_SPEND_VSIZE) {
        return std::numeric_limits<size_t>::max();
    }
    const size_t with_spends = DIRECT_SEND_BASE_VSIZE + (spend_count * DIRECT_SEND_SPEND_VSIZE);
    if (shielded_output_count > (std::numeric_limits<size_t>::max() - with_spends) / DIRECT_SEND_SHIELDED_OUTPUT_VSIZE) {
        return std::numeric_limits<size_t>::max();
    }
    const size_t with_outputs = with_spends + (shielded_output_count * DIRECT_SEND_SHIELDED_OUTPUT_VSIZE);
    if (transparent_output_bytes > std::numeric_limits<size_t>::max() - with_outputs) {
        return std::numeric_limits<size_t>::max();
    }
    return with_outputs + transparent_output_bytes;
}

} // namespace wallet
