// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FIRSTEDGE_H
#define BTX_MODELNET_SWARM_FIRSTEDGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note of one sender edge. edge_id names the edge. first_edge
 * says this is the sender's first edge. want_charge asks this note to
 * charge a fee.
 *
 * The sender's first edge adds no fee. Atoms stay 0. It does not charge.
 */
struct SwarmFirstEdge {
    std::string edge_id;
    bool first_edge{false};
    bool want_charge{false};
};

/**
 * Outcome of noting a first-edge fee. charged stays false and atoms
 * stays 0: the sender's first edge adds no fee.
 */
struct SwarmFirstEdgeResult {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note a first-edge fee without charging it.
 * Order, first match wins: an empty edge_id is EDGE. first_edge is
 * NO_FEE, even when want_charge is false. want_charge is HELD.
 * Otherwise the note is NOTED and err is clear.
 * charged stays false and atoms stays 0 on every path.
 * The sender's first edge adds no fee.
 */
SwarmFirstEdgeResult SwarmNoteFirstEdgeFee(const SwarmFirstEdge& edge, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FIRSTEDGE_H
