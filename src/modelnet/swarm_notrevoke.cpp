// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrevoke.h>

#include <string>

namespace modelnet {

SwarmNotRevokeResult SwarmNoteNotRevoke(const SwarmNotRevoke& note, std::string& err)
{
    SwarmNotRevokeResult result;
    result.allowed = false;
    // A revoked member reading a cache has not been shown on a live cache.
    if (note.member_id.empty()) {
        result.code = "MEMBER";
        result.allowed = false;
        err = "MEMBER";
        return result;
    }
    if (note.want_read) {
        result.code = "NOT_LIVE";
        result.allowed = false;
        err = "NOT_LIVE";
        return result;
    }
    result.code = "NOTED";
    result.allowed = false;
    err.clear();
    return result;
}

} // namespace modelnet
