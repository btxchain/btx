// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFIRSTEDGE_H
#define BTX_MODELNET_SWARM_NOTFIRSTEDGE_H

#include <string>

namespace modelnet {

/** Note that the sender's first edge adds no fee and no CLTV.
 *  charged stays false and cltv_delta stays 0.
 */
struct SwarmNotFirstEdge {
    std::string edge_id;
    bool first_edge{false};
    bool want_fee{false};
};

struct SwarmNotFirstEdgeResult {
    std::string code;
    bool charged{false};
    int cltv_delta{0};
};

/** Note a hop that does not charge a fee or add CLTV.
 *  Order, first match wins:
 *  1. An empty edge_id is EDGE. charged stays false, cltv_delta stays 0, and err is EDGE.
 *  2. first_edge is NO_FEE even when want_fee is false. charged stays false, cltv_delta stays 0, and err is NO_FEE.
 *  3. want_fee is NOT_CHARGED. charged stays false, cltv_delta stays 0, and err is NOT_CHARGED.
 *  4. Otherwise the note is NOTED. charged stays false, cltv_delta stays 0, and err is cleared.
 *  The sender's first edge adds no fee and no CLTV.
 */
SwarmNotFirstEdgeResult SwarmNoteNotFirstEdge(const SwarmNotFirstEdge& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFIRSTEDGE_H
