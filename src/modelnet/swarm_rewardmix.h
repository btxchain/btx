// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REWARDMIX_H
#define BTX_MODELNET_SWARM_REWARDMIX_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of a reward mix for one pool. pool_id names the pool.
 * The six ppm fields are parts per million: publish, train, eval,
 * data, route, and reserve. Together they must sum to 1000000.
 * want_pay asks this note to pay.
 *
 * paid stays false on every path. Nothing is signed and nothing is
 * broadcast. No hostnames or IPs are used.
 */
struct SwarmRewardMix {
    std::string pool_id;
    int64_t publish_ppm{0};
    int64_t train_ppm{0};
    int64_t eval_ppm{0};
    int64_t data_ppm{0};
    int64_t route_ppm{0};
    int64_t reserve_ppm{0};
    bool want_pay{false};
};

/**
 * Outcome of noting a reward mix. paid stays false: this note does
 * not pay, nothing is signed, and nothing is broadcast.
 */
struct SwarmRewardMixResult {
    bool paid{false};
    std::string code;
};

/**
 * Note a reward mix without paying, signing, or broadcasting.
 * Order, first match wins: an empty pool_id or any ppm below 0 is
 * MIX. Adding the six ppm values in a way that would overflow int64
 * is MIX. A sum other than 1000000 is SUM, even when want_pay is
 * true. want_pay is HELD and err is cleared. This note does not pay.
 * Otherwise the note is NOTED and err is cleared. paid stays false
 * on every path. Nothing is signed and nothing is broadcast.
 */
SwarmRewardMixResult SwarmNoteRewardMix(const SwarmRewardMix& mix, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REWARDMIX_H
