// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PRESSURE_H
#define BTX_MODELNET_SWARM_PRESSURE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A placement label only. bytes_moved stays false. measured_benchmark stays
 * false. This function does not copy a tensor and does not run a benchmark.
 */
struct SwarmPressureChoice {
    std::string choice;
    int64_t cost{0};
    bool bytes_moved{false};
    bool measured_benchmark{false};
    std::string code;
};

/**
 * Cost of each option is the supplied milliseconds plus missing_ppm/1000
 * plus memory_pressure plus copies. continuation_ppm reduces only the
 * idle-uncached cost, by continuation_ppm/1000, and that cost is floored
 * at 0. A negative input sets err to PRESSURE and leaves choice empty.
 * The minimum cost wins. Equal costs break in the order RECOMPUTE_LOCAL,
 * IDLE_UNCACHED, ROUTE_TO_OWNER, TRANSFER_KV.
 * TRANSFER_KV without an engine sets code to ENGINE_ABSENT. TRANSFER_KV
 * with an engine sets code to LOCAL. Every other winner leaves code empty.
 * err is cleared when a choice is returned.
 */
SwarmPressureChoice SwarmChoosePressured(int64_t recompute_ms, int64_t transfer_ms, int64_t route_ms,
                                         int64_t idle_uncached_ms, int missing_ppm, int memory_pressure, int copies,
                                         int continuation_ppm, bool engine_present, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PRESSURE_H
