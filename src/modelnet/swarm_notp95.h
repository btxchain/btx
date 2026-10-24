// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTP95_H
#define BTX_MODELNET_SWARM_NOTP95_H

#include <string>

namespace modelnet {

/**
 * A local note that a node might publish a latency percentile.
 * want_publish asks this note to publish a p50 or p95 figure.
 *
 * No p50 or p95 latency has been measured, so this note does not publish
 * one. published stays false on every path.
 */
struct SwarmNotP95 {
    std::string node_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unmeasured latency percentile. published stays
 * false on every path: no p50 or p95 latency has been measured, so this
 * note does not publish one.
 */
struct SwarmNotP95Result {
    std::string code;
    bool published{false};
};

/**
 * Note that no latency percentile is published.
 * Order, first match wins: an empty node_id is LATENCY. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false on every path. No p50 or p95 latency has been
 * measured, so this note does not publish one.
 */
SwarmNotP95Result SwarmNoteNotP95(const SwarmNotP95& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTP95_H
