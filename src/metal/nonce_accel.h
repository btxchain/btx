// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_NONCE_ACCEL_H
#define BITCOIN_METAL_NONCE_ACCEL_H

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#endif

namespace btx::metal {

inline uint64_t MulDivU64ByU32(uint64_t lhs, uint32_t rhs, uint32_t divisor)
{
    if (divisor == 0) {
        return std::numeric_limits<uint64_t>::max();
    }

#if defined(_MSC_VER) && !defined(__clang__)
    uint64_t high = 0;
    const uint64_t low = _umul128(lhs, static_cast<uint64_t>(rhs), &high);
    uint64_t remainder = 0;
    return _udiv128(high, low, divisor, &remainder);
#else
    const unsigned __int128 product =
        static_cast<unsigned __int128>(lhs) * static_cast<unsigned __int128>(rhs);
    return static_cast<uint64_t>(product / divisor);
#endif
}

struct NonceBatch {
    bool available{false};
    std::vector<uint64_t> nonces;
    std::string error;
};

struct NonceThresholdTuningRequest {
    uint64_t current_threshold{std::numeric_limits<uint64_t>::max()};
    uint32_t batch_size{0};
    uint32_t observed_candidates{0};
    uint32_t target_min_candidates{0};
    uint32_t target_max_candidates{0};
    uint32_t max_step_percent{25};
};

struct NonceThresholdTuningResult {
    uint64_t threshold{0};
    bool adjusted{false};
    std::string reason;
};

inline uint64_t ThresholdForCandidateCount(uint32_t candidate_count, uint32_t batch_size)
{
    if (batch_size == 0 || candidate_count == 0) {
        return 0;
    }
    if (candidate_count >= batch_size) {
        return std::numeric_limits<uint64_t>::max();
    }
    return MulDivU64ByU32(std::numeric_limits<uint64_t>::max(), candidate_count, batch_size);
}

inline NonceThresholdTuningResult TuneNoncePrefilterThreshold(const NonceThresholdTuningRequest& request)
{
    NonceThresholdTuningResult result;
    result.threshold = request.current_threshold;
    result.reason = "within_target_window";

    if (request.batch_size == 0) {
        result.reason = "batch_size_zero";
        return result;
    }

    const uint32_t observed = std::min(request.observed_candidates, request.batch_size);
    uint32_t target_min = std::min(request.target_min_candidates, request.batch_size);
    uint32_t target_max = std::min(request.target_max_candidates, request.batch_size);

    if (target_min == 0 && target_max == 0) {
        target_min = std::max<uint32_t>(1, request.batch_size / 32);
        target_max = std::max<uint32_t>(target_min, request.batch_size / 8);
    } else {
        if (target_min == 0) target_min = 1;
        if (target_max < target_min) target_max = target_min;
    }

    if (observed >= target_min && observed <= target_max) {
        return result;
    }

    const uint32_t target_mid = target_min + ((target_max - target_min) / 2);
    uint64_t proposed = request.current_threshold;

    if (observed == 0) {
        proposed = std::max<uint64_t>(request.current_threshold + (request.current_threshold < std::numeric_limits<uint64_t>::max() ? 1 : 0),
                                      ThresholdForCandidateCount(target_mid, request.batch_size));
        result.reason = "increase_zero_pass_rate";
    } else {
        proposed = MulDivU64ByU32(request.current_threshold, target_mid, observed);
        if (observed < target_min) {
            if (proposed <= request.current_threshold && request.current_threshold < std::numeric_limits<uint64_t>::max()) {
                proposed = request.current_threshold + 1;
            }
            result.reason = "increase_low_pass_rate";
        } else {
            if (proposed >= request.current_threshold && request.current_threshold > 0) {
                proposed = request.current_threshold - 1;
            }
            result.reason = "decrease_high_pass_rate";
        }
    }

    const uint32_t step_percent = std::clamp(request.max_step_percent, 1U, 100U);
    if (proposed > request.current_threshold) {
        const uint64_t span = std::numeric_limits<uint64_t>::max() - request.current_threshold;
        uint64_t max_step = MulDivU64ByU32(span, step_percent, 100U);
        if (max_step == 0 && request.current_threshold < std::numeric_limits<uint64_t>::max()) {
            max_step = 1;
        }
        const uint64_t cap = request.current_threshold > std::numeric_limits<uint64_t>::max() - max_step
            ? std::numeric_limits<uint64_t>::max()
            : request.current_threshold + max_step;
        result.threshold = std::min<uint64_t>(proposed, cap);
    } else if (proposed < request.current_threshold) {
        uint64_t max_step = MulDivU64ByU32(request.current_threshold, step_percent, 100U);
        if (max_step == 0 && request.current_threshold > 0) {
            max_step = 1;
        }
        const uint64_t floor = request.current_threshold > max_step ? request.current_threshold - max_step : 0;
        result.threshold = std::max<uint64_t>(proposed, floor);
    }

    result.adjusted = result.threshold != request.current_threshold;
    if (!result.adjusted) {
        result.reason = "no_adjustment";
    }
    return result;
}

NonceBatch GenerateNonceBatch(uint64_t start_nonce, uint32_t batch_size, uint64_t seed, uint64_t threshold);

} // namespace btx::metal

#endif // BITCOIN_METAL_NONCE_ACCEL_H
