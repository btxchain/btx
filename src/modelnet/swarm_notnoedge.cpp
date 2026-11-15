// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoedge.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoEdgeResult SwarmNoteNotNoEdge(const SwarmNotNoEdge& note, std::string& err)
{
    SwarmNotNoEdgeResult result;
    result.added = false;
    result.atoms = 0;
    // The sender's first edge adds no fee.
    if (note.edge_id.empty()) {
        result.code = "EDGE";
        result.added = false;
        result.atoms = 0;
        err = "EDGE";
        return result;
    }
    if (note.first_edge) {
        result.code = "NOT_ADDED";
        result.added = false;
        result.atoms = 0;
        err = "NOT_ADDED";
        return result;
    }
    if (note.want_add_fee) {
        result.code = "NOT_ADDED";
        result.added = false;
        result.atoms = 0;
        err = "NOT_ADDED";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
