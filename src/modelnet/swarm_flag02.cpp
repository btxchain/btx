// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag02.h>

#include <string>

namespace modelnet {

SwarmFlag02Result SwarmStageJoin(const SwarmFlag02& in, std::string& err)
{
    SwarmFlag02Result result;
    result.joined = false;
    result.connected = false;
    result.traversed = false;
    result.passed = false;
    result.bytes_moved = false;
    // Local family catalog. Do not open a socket or traverse NAT.
    if (in.family_id.empty() || in.peer_id.empty()) {
        result.code = "FAMILY";
        result.joined = false;
        result.connected = false;
        result.traversed = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "FAMILY";
        return result;
    }
    // A manual config request is refused.
    if (in.manual_config) {
        result.code = "MANUAL";
        result.joined = false;
        result.connected = false;
        result.traversed = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "MANUAL";
        return result;
    }
    if (in.want_connect) {
        result.code = "NO_SOCKET";
        result.joined = false;
        result.connected = false;
        result.traversed = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "NO_SOCKET";
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.joined = false;
        result.connected = false;
        result.traversed = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.joined = false;
    result.connected = false;
    result.traversed = false;
    result.passed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
