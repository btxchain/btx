// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEDGE_H
#define BTX_MODELNET_SWARM_NOTNOEDGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one edge. first_edge records the sender's first edge.
 * want_add_fee asks this note to add a fee.
 *
 * The sender's first edge adds no fee. added stays false and atoms stays 0
 * on every path.
 */
struct SwarmNotNoEdge {
    std::string edge_id;
    bool first_edge{false};
    bool want_add_fee{false};
};

/**
 * Outcome of noting an edge. added stays false and atoms stays 0 on
 * every path. The sender's first edge adds no fee.
 */
struct SwarmNotNoEdgeResult {
    std::string code;
    bool added{false};
    int64_t atoms{0};
};

/**
 * Note an edge without adding a fee. Order, first match wins: an empty
 * edge_id is EDGE. first_edge is NOT_ADDED even when want_add_fee is false.
 * want_add_fee is NOT_ADDED. Otherwise the note is NOTED and err is cleared.
 * added stays false and atoms stays 0 on every path. The sender's first
 * edge adds no fee.
 */
SwarmNotNoEdgeResult SwarmNoteNotNoEdge(const SwarmNotNoEdge& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEDGE_H
