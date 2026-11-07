// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCAPAB2_H
#define BTX_MODELNET_SWARM_NOTNOCAPAB2_H

#include <string>

namespace modelnet {

/**
 * A local note about one capability. uncovered marks a capability outside
 * the note. want_act asks this note to act.
 *
 * An uncovered capability acts on nothing. acted stays false on every path.
 */
struct SwarmNotNoCapab2 {
    std::string cap_id;
    bool uncovered{false};
    bool want_act{false};
};

/**
 * Outcome of noting a capability. acted stays false on every path.
 * An uncovered capability acts on nothing.
 */
struct SwarmNotNoCapab2Result {
    std::string code;
    bool acted{false};
};

/**
 * Note a capability without acting on it.
 * Order, first match wins: an empty cap_id is CAP. uncovered true is
 * NOT_ACTED even when want_act is false. want_act is HELD.
 * Otherwise the note is NOTED and err is cleared. acted stays false
 * on every path. An uncovered capability acts on nothing.
 */
SwarmNotNoCapab2Result SwarmNoteNotNoCapab2(const SwarmNotNoCapab2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCAPAB2_H
