// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOINTEGER2_H
#define BTX_MODELNET_SWARM_NOTNOINTEGER2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about frozen pairs. want_add asks this note to add a pair.
 * pair_id names the pair set.
 *
 * INTEGER_LINEAR stays eight frozen pairs. This note adds none.
 * added stays false and pairs stays 0 on every path.
 */
struct SwarmNotNoInteger2 {
    std::string pair_id;
    bool want_add{false};
};

/**
 * Outcome of noting frozen pairs. added stays false and pairs stays 0
 * on every path. INTEGER_LINEAR stays eight frozen pairs. This note
 * adds none.
 */
struct SwarmNotNoInteger2Result {
    std::string code;
    bool added{false};
    int64_t pairs{0};
};

/**
 * Note frozen pairs without adding any.
 * Order, first match wins: an empty pair_id is PAIR.
 * want_add is HELD. Otherwise the note is NOTED and err is cleared.
 * added stays false and pairs stays 0 on every path.
 * INTEGER_LINEAR stays eight frozen pairs. This note adds none.
 */
SwarmNotNoInteger2Result SwarmNoteNotNoInteger2(const SwarmNotNoInteger2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINTEGER2_H
