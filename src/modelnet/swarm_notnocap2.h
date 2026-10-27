// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCAP2_H
#define BTX_MODELNET_SWARM_NOTNOCAP2_H

#include <string>

namespace modelnet {

/**
 * A local note about one capability. covered marks a capability inside
 * the note. want_act asks this note to act.
 *
 * An uncovered capability acts on nothing. acted stays false and
 * bytes_moved stays false on every path.
 */
struct SwarmNotNoCap2 {
    std::string cap_id;
    bool covered{false};
    bool want_act{false};
};

/**
 * Outcome of noting a capability. acted stays false and bytes_moved
 * stays false on every path. An uncovered capability acts on nothing.
 */
struct SwarmNotNoCap2Result {
    std::string code;
    bool acted{false};
    bool bytes_moved{false};
};

/**
 * Note a capability without acting on it.
 * Order, first match wins: an empty cap_id is CAP. covered false is
 * NOT_ACTED even when want_act is false. want_act is HELD.
 * Otherwise the note is NOTED and err is cleared. acted stays false
 * and bytes_moved stays false on every path. An uncovered capability
 * acts on nothing.
 */
SwarmNotNoCap2Result SwarmNoteNotNoCap2(const SwarmNotNoCap2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCAP2_H
