// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_firstedge.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmFirstEdgeResult SwarmNoteFirstEdgeFee(const SwarmFirstEdge& edge, std::string& err)
{
    SwarmFirstEdgeResult result;
    result.charged = false;
    result.atoms = 0;
    // The sender's first edge adds no fee.
    if (edge.edge_id.empty()) {
        result.code = "EDGE";
        result.charged = false;
        result.atoms = 0;
        err = "EDGE";
        return result;
    }
    if (edge.first_edge) {
        result.code = "NO_FEE";
        result.charged = false;
        result.atoms = 0;
        err = "NO_FEE";
        return result;
    }
    if (edge.want_charge) {
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
