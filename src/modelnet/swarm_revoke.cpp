// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revoke.h>

namespace modelnet {

// A revoked member reads no later page.
SwarmRevokeResult SwarmNoteRevoke(const SwarmRevoke& member, std::string& err)
{
    SwarmRevokeResult result;
    result.read = false;
    if (member.member_id.empty()) {
        result.code = "MEMBER";
        result.read = false;
        err = "MEMBER";
        return result;
    }
    if (member.revoked) {
        result.code = "NOT_READ";
        result.read = false;
        err = "NOT_READ";
        return result;
    }
    if (member.want_read) {
        result.code = "HELD";
        result.read = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.read = false;
    err.clear();
    return result;
}

} // namespace modelnet
