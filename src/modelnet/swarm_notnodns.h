// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODNS_H
#define BTX_MODELNET_SWARM_NOTNODNS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one seed. want_fill asks this note to fill it.
 *
 * Model DNS seeds stay empty. Filling them is refused.
 * filled stays false and seeds stays 0 on every path.
 */
struct SwarmNotNoDns {
    std::string seed_id;
    bool want_fill{false};
};

/**
 * Outcome of noting a seed. filled stays false and seeds stays 0
 * on every path. Model DNS seeds stay empty. Filling them is refused.
 */
struct SwarmNotNoDnsResult {
    std::string code;
    bool filled{false};
    int64_t seeds{0};
};

/**
 * Note a seed without filling model DNS seeds.
 * Order, first match wins: an empty seed_id is SEED.
 * want_fill is EMPTY.
 * Otherwise the note is NOTED and err is cleared.
 * filled stays false and seeds stays 0 on every path.
 * Model DNS seeds stay empty. Filling them is refused.
 */
SwarmNotNoDnsResult SwarmNoteNotNoDns(const SwarmNotNoDns& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODNS_H
