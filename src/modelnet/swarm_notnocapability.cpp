// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocapability.h>

#include <string>

namespace modelnet {

SwarmNotNoCapabilityResult SwarmNoteNotNoCapability(const SwarmNotNoCapability& note, std::string& err)
{
    // An action outside the capability acts on nothing and moves no bytes.
    SwarmNotNoCapabilityResult result;
    result.acted = false;
    result.bytes_moved = false;
    if (note.action_id.empty()) {
        result.code = "ACTION";
        result.acted = false;
        result.bytes_moved = false;
        err = "ACTION";
        return result;
    }
    if (!note.covered) {
        result.code = "AUTHORITY";
        result.acted = false;
        result.bytes_moved = false;
        err = "AUTHORITY";
        return result;
    }
    if (note.want_act) {
        result.code = "HELD";
        result.acted = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.acted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
