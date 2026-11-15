// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofirstedge.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoFirstEdgeResult SwarmNoteNotNoFirstEdge(const SwarmNotNoFirstEdge& note, std::string& err)
{
    SwarmNotNoFirstEdgeResult result;
    result.charged = false;
    result.atoms = 0;
    // The sender's first edge adds no fee and no CLTV.
    if (note.edge_id.empty()) {
        result.code = "EDGE";
        result.charged = false;
        result.atoms = 0;
        err = "EDGE";
        return result;
    }
    if (note.first_edge) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    if (note.want_charge) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
