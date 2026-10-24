// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLTV_H
#define BTX_MODELNET_SWARM_NOTNOCLTV_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one edge. first_edge records the sender's first edge.
 * want_add_cltv asks this note to add a CLTV.
 *
 * The sender's first edge adds no CLTV. added stays false and blocks stays 0
 * on every path.
 */
struct SwarmNotNoCltv {
    std::string edge_id;
    bool first_edge{false};
    bool want_add_cltv{false};
};

/**
 * Outcome of noting an edge. added stays false and blocks stays 0 on
 * every path. The sender's first edge adds no CLTV.
 */
struct SwarmNotNoCltvResult {
    std::string code;
    bool added{false};
    int64_t blocks{0};
};

/**
 * Note an edge without adding a CLTV. Order, first match wins: an empty
 * edge_id is EDGE. first_edge is NOT_ADDED even when want_add_cltv is false.
 * want_add_cltv is NOT_ADDED. Otherwise the note is NOTED and err is cleared.
 * added stays false and blocks stays 0 on every path. The sender's first
 * edge adds no CLTV.
 */
SwarmNotNoCltvResult SwarmNoteNotNoCltv(const SwarmNotNoCltv& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLTV_H
