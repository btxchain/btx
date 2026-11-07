// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMASSEXIT_H
#define BTX_MODELNET_SWARM_NOTNOMASSEXIT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one island. assumed_size marks a caller-supplied
 * mass-exit size. want_measure asks this note to measure that exit.
 *
 * An assumed mass-exit size, including 8000 bytes, is not a measurement
 * and moves no bytes. measured stays false and bytes stays 0 on every path.
 */
struct SwarmNotNoMassExit {
    std::string island_id;
    bool assumed_size{false};
    bool want_measure{false};
};

/**
 * Outcome of noting a mass exit. measured stays false and bytes stays 0
 * on every path. An assumed mass-exit size, including 8000 bytes, is not
 * a measurement and moves no bytes.
 */
struct SwarmNotNoMassExitResult {
    std::string code;
    bool measured{false};
    int64_t bytes{0};
};

/**
 * Note a mass exit without measuring it or moving bytes.
 * Order, first match wins:
 * 1. An empty island_id is ISLAND. measured stays false, bytes stays 0,
 *    and err is ISLAND.
 * 2. If assumed_size is true, the note is UNMEASURED even when
 *    want_measure is false. measured stays false, bytes stays 0, and err
 *    is UNMEASURED.
 * 3. want_measure is UNMEASURED. measured stays false, bytes stays 0, and
 *    err is UNMEASURED.
 * 4. Otherwise the note is NOTED and err is cleared. measured stays false
 *    and bytes stays 0.
 * An assumed mass-exit size, including 8000 bytes, is not a measurement
 * and moves no bytes.
 */
SwarmNotNoMassExitResult SwarmNoteNotNoMassExit(const SwarmNotNoMassExit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMASSEXIT_H
