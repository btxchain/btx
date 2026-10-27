// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcontrib.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotContribResult SwarmNoteNotContrib(const SwarmNotContrib& note, std::string& err)
{
    SwarmNotContribResult result;
    result.published = false;
    result.accepted = false;
    result.count = 0;
    // Contributions stay unpublished and unaccepted.
    if (note.worker_id.empty()) {
        result.code = "WORKER";
        result.published = false;
        result.accepted = false;
        result.count = 0;
        err = "WORKER";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNVERIFIED";
        result.published = false;
        result.accepted = false;
        result.count = 0;
        err = "UNVERIFIED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.accepted = false;
    result.count = 0;
    err.clear();
    return result;
}

} // namespace modelnet
