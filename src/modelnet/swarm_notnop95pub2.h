// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOP95PUB2_H
#define BTX_MODELNET_SWARM_NOTNOP95PUB2_H

#include <string>

namespace modelnet {

/**
 * A local note about p95 latency for one sample. sample_id names the
 * sample. want_publish asks this note to publish a p95 latency.
 *
 * This note publishes no p95 latency. published stays false on every path.
 */
struct SwarmNotNoP95Pub2 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting p95 latency. published stays false on every path.
 * This note publishes no p95 latency.
 */
struct SwarmNotNoP95Pub2Result {
    std::string code;
    bool published{false};
};

/**
 * Note a sample without publishing a p95 latency.
 * Order, first match wins: an empty sample_id is SAMPLE. want_publish is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * published stays false on every path.
 * This note publishes no p95 latency.
 */
SwarmNotNoP95Pub2Result SwarmNoteNotNoP95Pub2(const SwarmNotNoP95Pub2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOP95PUB2_H
