// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCLTVFIRST2_H
#define BTX_MODELNET_SWARM_NOTNOCLTVFIRST2_H

#include <string>

namespace modelnet {

/**
 * A local note about one edge. first_edge records the sender first edge.
 * want_add asks this note to add a CLTV.
 *
 * The sender first edge adds no CLTV. added stays false on every path.
 */
struct SwarmNotNoCltvFirst2 {
    std::string edge_id;
    bool first_edge{false};
    bool want_add{false};
};

/**
 * Outcome of noting an edge. added stays false on every path.
 * The sender first edge adds no CLTV.
 */
struct SwarmNotNoCltvFirst2Result {
    std::string code;
    bool added{false};
};

/**
 * Note an edge without adding a CLTV. Order, first match wins: an empty
 * edge_id is EDGE. first_edge is NOT_ADDED even when want_add is false.
 * want_add is HELD. Otherwise the note is NOTED and err is cleared.
 * added stays false on every path. The sender first edge adds no CLTV.
 */
SwarmNotNoCltvFirst2Result SwarmNoteNotNoCltvFirst2(const SwarmNotNoCltvFirst2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCLTVFIRST2_H
