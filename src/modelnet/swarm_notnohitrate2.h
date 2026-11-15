// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHITRATE2_H
#define BTX_MODELNET_SWARM_NOTNOHITRATE2_H

#include <string>

namespace modelnet {

/**
 * A local note that a unit might publish a cache hit rate.
 * sample_id names the sample. want_publish asks this note to publish one.
 *
 * A unit note publishes no cache hit rate.
 * published stays false and hits stays 0 on every path.
 */
struct SwarmNotNoHitRate2 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unpublished cache hit rate. published stays false
 * and hits stays 0 on every path: a unit note publishes no cache hit rate.
 */
struct SwarmNotNoHitRate2Result {
    std::string code;
    bool published{false};
    int hits{0};
};

/**
 * Note that no cache hit rate is published.
 * Order, first match wins: an empty sample_id is SAMPLE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is cleared.
 * published stays false and hits stays 0 on every path. A unit note
 * publishes no cache hit rate.
 */
SwarmNotNoHitRate2Result SwarmNoteNotNoHitRate2(const SwarmNotNoHitRate2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHITRATE2_H
