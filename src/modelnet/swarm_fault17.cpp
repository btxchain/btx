// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault17.h>

namespace modelnet {

SwarmFault17Result SwarmRecoverFault17(const SwarmFault17& in, std::string& err)
{
    SwarmFault17Result result;
    // A formerly authorized member gets no new cache access after revocation.
    result.allowed = false;
    result.bytes_moved = false;
    result.broadcast = false;

    if (in.member_id.empty() || in.page_id.empty()) {
        result.code = "MEMBER";
        result.allowed = false;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "MEMBER";
        return result;
    }
    if (in.revoked) {
        result.code = "REVOKED";
        result.allowed = false;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "REVOKED";
        return result;
    }
    if (in.want_read) {
        result.code = "HELD";
        result.allowed = false;
        result.bytes_moved = false;
        result.broadcast = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.allowed = false;
    result.bytes_moved = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
