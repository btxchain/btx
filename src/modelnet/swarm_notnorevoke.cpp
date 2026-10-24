// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorevoke.h>

#include <string>

namespace modelnet {

SwarmNotNoRevokeResult SwarmNoteNotNoRevoke(const SwarmNotNoRevoke& note, std::string& err)
{
    SwarmNotNoRevokeResult result;
    result.revoked = false;
    result.broadcast = false;
    // This note revokes nothing and broadcasts nothing.
    if (note.grant_id.empty()) {
        result.code = "GRANT";
        result.revoked = false;
        result.broadcast = false;
        err = "GRANT";
        return result;
    }
    if (note.want_revoke) {
        result.code = "HELD";
        result.revoked = false;
        result.broadcast = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.revoked = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
