// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_COST_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_COST_H

#include <cstdint>
#include <string>

namespace modelnet {

/** Four adjusted placement costs. Idle is already floored at 0. */
struct SwarmKvPlaceCosts {
    std::int64_t recompute{0};
    std::int64_t idle{0};
    std::int64_t route{0};
    std::int64_t transfer{0};
};

/**
 * Adjust the four bases.
 * Each cost is base + missing_ppm/1000 + memory_pressure + copies.
 * Continuation is subtracted from the idle cost only, then that cost is floored at 0.
 * Continuation does not reduce recompute, route, or transfer.
 * A negative recompute, idle, route, transfer, missing_ppm, memory_pressure, or copies
 * is PRESSURE. An unrepresentable sum is PRESSURE. On failure out is left unchanged.
 */
bool SwarmKvPlaceAdjust(std::int64_t recompute, std::int64_t idle, std::int64_t route, std::int64_t transfer,
                        std::int64_t missing_ppm, std::int64_t memory_pressure, std::int64_t copies,
                        std::int64_t continuation, SwarmKvPlaceCosts& out, std::string& err);

/**
 * Minimum cost. Ties prefer recompute, then idle, then route, then transfer.
 * The name is "recompute", "idle", "route", or "transfer".
 */
std::string SwarmKvPlacePick(const SwarmKvPlaceCosts& costs);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_COST_H
