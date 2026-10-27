// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notprivateoff.h>

#include <string>

namespace modelnet {

SwarmNotPrivateOffResult SwarmNoteNotPrivateOff(const SwarmNotPrivateOff& note, std::string& err)
{
    SwarmNotPrivateOffResult result;
    result.accepted = false;
    result.stored = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.accepted = false;
        result.stored = false;
        err = "NODE";
        return result;
    }
    // Private prompts stay off by default. This note stores no prompt.
    if (note.want_private) {
        result.code = "PRIVATE_OFF";
        result.accepted = false;
        result.stored = false;
        err = "PRIVATE_OFF";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.stored = false;
    err.clear();
    return result;
}

} // namespace modelnet
