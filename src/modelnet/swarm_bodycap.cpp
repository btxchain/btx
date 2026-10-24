// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodycap.h>

namespace modelnet {

SwarmBodyCapResult SwarmKeepBodyCap(const SwarmBodyCap& body, std::string& err)
{
    // The body cap stays 33554432 bytes.
    SwarmBodyCapResult result;
    result.raised = false;
    result.bytes = 33554432;
    if (body.body_id.empty()) {
        result.code = "BODY";
        result.raised = false;
        result.bytes = 33554432;
        err = "BODY";
        return result;
    }
    if (body.want_raise) {
        result.code = "HELD";
        result.raised = false;
        result.bytes = 33554432;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.bytes = 33554432;
    err.clear();
    return result;
}

} // namespace modelnet
