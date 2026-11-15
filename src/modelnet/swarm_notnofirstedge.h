// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFIRSTEDGE_H
#define BTX_MODELNET_SWARM_NOTNOFIRSTEDGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one edge. first_edge records the sender's first edge.
 * want_charge asks this note to charge a fee.
 *
 * The sender's first edge adds no fee and no CLTV. charged stays false and
 * atoms stays 0 on every path.
 */
struct SwarmNotNoFirstEdge {
    std::string edge_id;
    bool first_edge{false};
    bool want_charge{false};
};

/**
 * Outcome of noting an edge. charged stays false and atoms stays 0 on
 * every path. The sender's first edge adds no fee and no CLTV.
 */
struct SwarmNotNoFirstEdgeResult {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note an edge without charging a fee or adding a CLTV. Order, first match
 * wins: an empty edge_id is EDGE. first_edge is NOT_CHARGED even when
 * want_charge is false. want_charge is NOT_CHARGED. Otherwise the note is
 * NOTED and err is cleared. charged stays false and atoms stays 0 on every
 * path. The sender's first edge adds no fee and no CLTV.
 */
SwarmNotNoFirstEdgeResult SwarmNoteNotNoFirstEdge(const SwarmNotNoFirstEdge& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFIRSTEDGE_H
