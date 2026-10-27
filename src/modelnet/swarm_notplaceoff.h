// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPLACEOFF_H
#define BTX_MODELNET_SWARM_NOTPLACEOFF_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one run. want_publish asks this note to publish a
 * comparison with workflow-aware placement disabled.
 *
 * A comparison with workflow-aware placement disabled has not been measured.
 * published stays false, delta stays 0, and bytes_moved stays false on every path.
 */
struct SwarmNotPlaceOff {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a placement-off comparison. published stays false, delta
 * stays 0, and bytes_moved stays false on every path.
 */
struct SwarmNotPlaceOffResult {
    std::string code;
    bool published{false};
    int64_t delta{0};
    bool bytes_moved{false};
};

/**
 * Note a placement-off comparison without measuring or publishing.
 * Order, first match wins: an empty run_id is RUN.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published stays false, delta stays 0, and bytes_moved stays false on every path.
 * A comparison with workflow-aware placement disabled has not been measured.
 */
SwarmNotPlaceOffResult SwarmNoteNotPlaceOff(const SwarmNotPlaceOff& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPLACEOFF_H
