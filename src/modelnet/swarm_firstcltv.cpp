// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_firstcltv.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmFirstCltvResult SwarmNoteFirstCltv(const SwarmFirstCltv& edge, std::string& err)
{
    SwarmFirstCltvResult result;
    result.added = false;
    result.delay = 0;
    // The sender's first edge adds no CLTV.
    if (edge.edge_id.empty()) {
        result.code = "EDGE";
        result.added = false;
        result.delay = 0;
        err = "EDGE";
        return result;
    }
    if (edge.first_edge) {
        result.code = "NOT_ADDED";
        result.added = false;
        result.delay = 0;
        err = "NOT_ADDED";
        return result;
    }
    if (edge.want_add) {
        result.code = "HELD";
        result.added = false;
        result.delay = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    result.delay = 0;
    err.clear();
    return result;
}

} // namespace modelnet
