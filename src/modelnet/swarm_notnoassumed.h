// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOASSUMED_H
#define BTX_MODELNET_SWARM_NOTNOASSUMED_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one run. assumed marks a caller-supplied mass-exit
 * size. want_publish asks this note to publish that exit.
 *
 * An assumed mass-exit size is not a measurement.
 * published stays false and exits stays 0 on every path.
 */
struct SwarmNotNoAssumed {
    std::string run_id;
    bool assumed{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a run. published stays false and exits stays 0 on
 * every path. An assumed mass-exit size is not a measurement.
 */
struct SwarmNotNoAssumedResult {
    std::string code;
    bool published{false};
    int64_t exits{0};
};

/**
 * Note a run without publishing it or recording an assumed exit size.
 * Order, first match wins:
 * 1. An empty run_id is RUN. published stays false, exits stays 0, and
 *    err is RUN.
 * 2. If assumed is true, the note is UNMEASURED even when want_publish
 *    is false. published stays false, exits stays 0, and err is
 *    UNMEASURED.
 * 3. want_publish is HELD. published stays false, exits stays 0, and err
 *    is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. published stays
 *    false and exits stays 0.
 * An assumed mass-exit size is not a measurement.
 */
SwarmNotNoAssumedResult SwarmNoteNotNoAssumed(const SwarmNotNoAssumed& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOASSUMED_H
