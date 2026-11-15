// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFIRSTEDGE2_H
#define BTX_MODELNET_SWARM_NOTNOFIRSTEDGE2_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one edge. first_edge records the sender's first edge.
 * want_charge asks this note to charge a fee.
 *
 * The sender first edge adds no fee. charged stays false and atoms stays 0
 * on every path.
 */
struct SwarmNotNoFirstEdge2 {
    std::string edge_id;
    bool first_edge{false};
    bool want_charge{false};
};

/**
 * Outcome of noting an edge. charged stays false and atoms stays 0 on
 * every path. The sender first edge adds no fee.
 */
struct SwarmNotNoFirstEdge2Result {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note an edge without charging a fee. Order, first match wins: an empty
 * edge_id is EDGE. first_edge is NOT_CHARGED even when want_charge is
 * false. want_charge is HELD. Otherwise the note is NOTED and err is
 * cleared. charged stays false and atoms stays 0 on every path. The
 * sender first edge adds no fee.
 */
SwarmNotNoFirstEdge2Result SwarmNoteNotNoFirstEdge2(const SwarmNotNoFirstEdge2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFIRSTEDGE2_H
