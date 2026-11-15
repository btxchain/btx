// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofirstedge2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoFirstEdge2Result SwarmNoteNotNoFirstEdge2(const SwarmNotNoFirstEdge2& note, std::string& err)
{
    SwarmNotNoFirstEdge2Result result;
    result.charged = false;
    result.atoms = 0;
    // The sender first edge adds no fee.
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
        result.code = "HELD";
        result.charged = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
