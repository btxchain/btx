// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCAPACT2_H
#define BTX_MODELNET_SWARM_NOTNOCAPACT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one capability. uncovered marks a capability this
 * note does not cover. want_act asks this note to act.
 *
 * An uncovered capability acts on nothing. acted stays false on every path.
 */
struct SwarmNotNoCapAct2 {
    std::string capability_id;
    bool uncovered{false};
    bool want_act{false};
};

/**
 * Outcome of noting a capability. acted stays false on every path.
 * An uncovered capability acts on nothing.
 */
struct SwarmNotNoCapAct2Result {
    std::string code;
    bool acted{false};
};

/**
 * Note a capability without acting on it.
 * Order, first match wins: an empty capability_id is CAPABILITY.
 * uncovered true is NOT_ACTED even when want_act is false. want_act is
 * HELD. Otherwise the note is NOTED and err is cleared. acted stays
 * false on every path. An uncovered capability acts on nothing.
 */
SwarmNotNoCapAct2Result SwarmNoteNotNoCapAct2(const SwarmNotNoCapAct2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCAPACT2_H
