// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTCOORDOFF_H
#define BITCOIN_MODELNET_SWARM_NOTCOORDOFF_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one run. want_publish asks this note to publish a
 * comparison with coordination disabled.
 *
 * A comparison with coordination disabled has not been measured.
 * published stays false and delta stays 0 on every path.
 */
struct SwarmNotCoordOff {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a coordination-disabled comparison. published stays
 * false and delta stays 0: a comparison with coordination disabled has
 * not been measured.
 */
struct SwarmNotCoordOffResult {
    std::string code;
    bool published{false};
    int64_t delta{0};
};

/**
 * Note a coordination-disabled comparison without measuring it. Order,
 * first match wins: an empty run_id is RUN. want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is cleared. published stays false
 * and delta stays 0 on every path. A comparison with coordination
 * disabled has not been measured.
 */
SwarmNotCoordOffResult SwarmNoteNotCoordOff(const SwarmNotCoordOff& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTCOORDOFF_H
