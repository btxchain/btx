// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOP502_H
#define BTX_MODELNET_SWARM_NOTNOP502_H

#include <string>

namespace modelnet {

/**
 * A local note about p50 for one sample. want_publish asks this
 * note to publish a p50 measurement.
 *
 * A unit note publishes no p50. published stays false and
 * p50_us stays 0 on every path.
 */
struct SwarmNotNoP502 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting p50. published stays false and p50_us stays 0
 * on every path.
 */
struct SwarmNotNoP502Result {
    std::string code;
    bool published{false};
    int p50_us{0};
};

/**
 * Note a sample without publishing a p50 measurement.
 * Order, first match wins: an empty sample_id is SAMPLE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is cleared.
 * published stays false and p50_us stays 0 on every path.
 * A unit note publishes no p50.
 */
SwarmNotNoP502Result SwarmNoteNotNoP502(const SwarmNotNoP502& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOP502_H
