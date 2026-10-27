// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHITRATE_H
#define BTX_MODELNET_SWARM_NOTNOHITRATE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a unit might publish a cache hit rate.
 * run_id names the run. want_publish asks this note to publish one.
 *
 * A unit note publishes no cache hit rate.
 * published stays false and hits stays 0 on every path.
 */
struct SwarmNotNoHitRate {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unpublished cache hit rate. published stays false
 * and hits stays 0 on every path: a unit note publishes no cache hit rate.
 */
struct SwarmNotNoHitRateResult {
    std::string code;
    bool published{false};
    int64_t hits{0};
};

/**
 * Note that no cache hit rate is published.
 * Order, first match wins: an empty run_id is RUN. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is cleared.
 * published stays false and hits stays 0 on every path. A unit note
 * publishes no cache hit rate.
 */
SwarmNotNoHitRateResult SwarmNoteNotNoHitRate(const SwarmNotNoHitRate& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHITRATE_H
