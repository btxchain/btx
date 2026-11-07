// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREPEAT_H
#define BTX_MODELNET_SWARM_NOTREPEAT_H

#include <string>

namespace modelnet {

/**
 * A local note about one parent. want_repeat asks this note to use a
 * graduated model as the parent of a second research cycle.
 *
 * A second research cycle has not used a graduated model as its parent.
 * repeated stays false on every path.
 */
struct SwarmNotRepeat {
    std::string parent_id;
    bool want_repeat{false};
};

/**
 * Outcome of noting a repeat request. repeated stays false on every path:
 * a second research cycle has not used a graduated model as its parent.
 */
struct SwarmNotRepeatResult {
    std::string code;
    bool repeated{false};
};

/**
 * Note a repeat request without using a graduated model as the parent.
 * Order, first match wins: an empty parent_id is PARENT. want_repeat is
 * NOT_REPEATED. Otherwise the note is NOTED and err is clear.
 * repeated stays false on every path.
 */
SwarmNotRepeatResult SwarmNoteNotRepeat(const SwarmNotRepeat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREPEAT_H
