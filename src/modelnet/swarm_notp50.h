// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTP50_H
#define BTX_MODELNET_SWARM_NOTP50_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a run might publish a p50 latency.
 * want_publish asks this note to publish a p50 figure.
 *
 * No p50 latency has been measured, so this note does not publish one.
 * published stays false and latency_us stays 0 on every path.
 */
struct SwarmNotP50 {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unmeasured p50 latency. published stays false and
 * latency_us stays 0 on every path: no p50 latency has been measured, so
 * this note does not publish one.
 */
struct SwarmNotP50Result {
    std::string code;
    bool published{false};
    int64_t latency_us{0};
};

/**
 * Note that no p50 latency is published.
 * Order, first match wins: an empty run_id is LATENCY. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and latency_us stays 0 on every path. No p50
 * latency has been measured, so this note does not publish one.
 */
SwarmNotP50Result SwarmNoteNotP50(const SwarmNotP50& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTP50_H
