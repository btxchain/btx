// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault19.h>

#include <string>

namespace modelnet {

SwarmFault19Result SwarmRecoverFault19(const SwarmFault19& in, std::string& err)
{
    SwarmFault19Result result;
    // A false-compatibility advertisement never shares, moves bytes, or connects.
    result.shared = false;
    result.bytes_moved = false;
    result.connected = false;
    if (in.peer_id.empty()) {
        result.code = "PEER";
        result.shared = false;
        result.bytes_moved = false;
        result.connected = false;
        err = "PEER";
        return result;
    }
    if (in.advertised_compatible && !in.actually_compatible) {
        result.code = "FAMILY_NOT_COMPAT";
        result.shared = false;
        result.bytes_moved = false;
        result.connected = false;
        err = "FAMILY_NOT_COMPAT";
        return result;
    }
    if (in.want_share) {
        result.code = "HELD";
        result.shared = false;
        result.bytes_moved = false;
        result.connected = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    result.connected = false;
    err.clear();
    return result;
}

} // namespace modelnet
