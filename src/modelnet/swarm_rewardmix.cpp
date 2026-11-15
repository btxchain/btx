// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rewardmix.h>

#include <cstdint>

namespace modelnet {

SwarmRewardMixResult SwarmNoteRewardMix(const SwarmRewardMix& mix, std::string& err)
{
    SwarmRewardMixResult result;
    result.paid = false;
    if (mix.pool_id.empty() || mix.publish_ppm < 0 || mix.train_ppm < 0 || mix.eval_ppm < 0 ||
        mix.data_ppm < 0 || mix.route_ppm < 0 || mix.reserve_ppm < 0) {
        result.code = "MIX";
        result.paid = false;
        err = "MIX";
        return result;
    }
    // The six parts are non-negative. Stop before the running sum
    // would pass INT64_MAX. An overflowing add is MIX.
    const int64_t parts[6] = {
        mix.publish_ppm, mix.train_ppm, mix.eval_ppm, mix.data_ppm, mix.route_ppm, mix.reserve_ppm,
    };
    int64_t sum = 0;
    for (const int64_t part : parts) {
        if (part > INT64_MAX - sum) {
            result.code = "MIX";
            result.paid = false;
            err = "MIX";
            return result;
        }
        sum += part;
    }
    // A sum other than 1000000 is SUM even when want_pay is true.
    // Nothing is signed and nothing is broadcast.
    if (sum != 1000000) {
        result.code = "SUM";
        result.paid = false;
        err = "SUM";
        return result;
    }
    if (mix.want_pay) {
        result.code = "HELD";
        result.paid = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    err.clear();
    return result;
}

} // namespace modelnet
