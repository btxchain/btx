// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogrant.h>

#include <string>

namespace modelnet {

SwarmNotNoGrantResult SwarmNoteNotNoGrant(const SwarmNotNoGrant& note, std::string& err)
{
    SwarmNotNoGrantResult result;
    result.granted = false;
    result.trained = false;
    // A download license is not a training grant.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.granted = false;
        result.trained = false;
        err = "LICENSE";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_GRANT";
        result.granted = false;
        result.trained = false;
        err = "NOT_GRANT";
        return result;
    }
    result.code = "NOTED";
    result.granted = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
