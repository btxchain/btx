// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notadopt.h>

#include <string>

namespace modelnet {

SwarmNotAdoptResult SwarmNoteNotAdopt(const SwarmNotAdopt& note, std::string& err)
{
    SwarmNotAdoptResult result;
    result.adopted = false;
    // Follow-staging has not adopted a qualified descendant on a second node.
    if (note.descendant_id.empty()) {
        result.code = "DESCENDANT";
        result.adopted = false;
        err = "DESCENDANT";
        return result;
    }
    if (note.want_adopt) {
        result.code = "NOT_ADOPTED";
        result.adopted = false;
        err = "NOT_ADOPTED";
        return result;
    }
    result.code = "NOTED";
    result.adopted = false;
    err.clear();
    return result;
}

} // namespace modelnet
