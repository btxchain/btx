// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOP50_H
#define BTX_MODELNET_SWARM_NOTNOP50_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about p50 latency for one run. want_publish asks this
 * note to publish a p50 latency measurement.
 *
 * A unit note publishes no p50 latency. published stays false and
 * milliseconds stays 0 on every path.
 */
struct SwarmNotNoP50 {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting p50 latency. published stays false and milliseconds
 * stays 0 on every path.
 */
struct SwarmNotNoP50Result {
    std::string code;
    bool published{false};
    int64_t milliseconds{0};
};

/**
 * Note a run without publishing a p50 latency measurement.
 * Order, first match wins: an empty run_id is RUN. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and milliseconds stays 0 on every path.
 * A unit note publishes no p50 latency.
 */
SwarmNotNoP50Result SwarmNoteNotNoP50(const SwarmNotNoP50& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOP50_H
