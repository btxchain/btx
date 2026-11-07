// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostaleep.h>

#include <string>

namespace modelnet {

SwarmNotNoStaleEpResult SwarmNoteNotNoStaleEp(const SwarmNotNoStaleEp& note, std::string& err)
{
    SwarmNotNoStaleEpResult result;
    result.admitted = false;
    result.trained = false;
    // admitted and trained stay false on every path. A stale-epoch lease
    // admits no member and does not train.
    if (note.lease_id.empty()) {
        result.code = "LEASE";
        result.admitted = false;
        result.trained = false;
        err = "LEASE";
        return result;
    }
    if (note.stale_epoch) {
        result.code = "STALE_EPOCH";
        result.admitted = false;
        result.trained = false;
        err = "STALE_EPOCH";
        return result;
    }
    if (note.want_admit) {
        result.code = "HELD";
        result.admitted = false;
        result.trained = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.admitted = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
