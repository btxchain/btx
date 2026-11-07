// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfirstedge.h>

namespace modelnet {

SwarmNotFirstEdgeResult SwarmNoteNotFirstEdge(const SwarmNotFirstEdge& note, std::string& err)
{
    // The sender's first edge adds no fee and no CLTV.
    SwarmNotFirstEdgeResult out;
    out.charged = false;
    out.cltv_delta = 0;

    if (note.edge_id.empty()) {
        out.code = "EDGE";
        err = "EDGE";
        return out;
    }
    if (note.first_edge) {
        out.code = "NO_FEE";
        err = "NO_FEE";
        return out;
    }
    if (note.want_fee) {
        out.code = "NOT_CHARGED";
        err = "NOT_CHARGED";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
