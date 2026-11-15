// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCAPABILITY_H
#define BTX_MODELNET_SWARM_NOTNOCAPABILITY_H

#include <string>

namespace modelnet {

/**
 * A local note about one action. want_act asks this note to act.
 * covered marks an action inside the capability.
 *
 * An action outside the capability acts on nothing and moves no bytes, so
 * acted stays false and bytes_moved stays false on every path.
 */
struct SwarmNotNoCapability {
    std::string action_id;
    bool covered{false};
    bool want_act{false};
};

/**
 * Outcome of noting an action. acted stays false and bytes_moved stays
 * false on every path. An action outside the capability acts on nothing
 * and moves no bytes.
 */
struct SwarmNotNoCapabilityResult {
    std::string code;
    bool acted{false};
    bool bytes_moved{false};
};

/**
 * Note an action without acting on it.
 * Order, first match wins: an empty action_id is ACTION. covered false is
 * AUTHORITY even when want_act is false. want_act is HELD.
 * Otherwise the note is NOTED and err is cleared. acted stays false
 * and bytes_moved stays false on every path. An action outside the
 * capability acts on nothing and moves no bytes.
 */
SwarmNotNoCapabilityResult SwarmNoteNotNoCapability(const SwarmNotNoCapability& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCAPABILITY_H
