// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOP952_H
#define BTX_MODELNET_SWARM_NOTNOP952_H

#include <string>

namespace modelnet {

/**
 * A local note about p95 for one sample. want_publish asks this
 * note to publish a p95 measurement.
 *
 * A unit note publishes no p95. published stays false and
 * p95_us stays 0 on every path.
 */
struct SwarmNotNoP952 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting p95. published stays false and p95_us stays 0
 * on every path.
 */
struct SwarmNotNoP952Result {
    std::string code;
    bool published{false};
    int p95_us{0};
};

/**
 * Note a sample without publishing a p95 measurement.
 * Order, first match wins: an empty sample_id is SAMPLE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is cleared.
 * published stays false and p95_us stays 0 on every path.
 * A unit note publishes no p95.
 */
SwarmNotNoP952Result SwarmNoteNotNoP952(const SwarmNotNoP952& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOP952_H
