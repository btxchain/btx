// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMULTIHOPQUAL2_H
#define BTX_MODELNET_SWARM_NOTNOMULTIHOPQUAL2_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. want_qualify asks this note to qualify
 * a multi-hop route.
 *
 * Multi-hop qualification stays false and this note qualifies nothing.
 * qualified stays false on every path.
 */
struct SwarmNotNoMultiHopQual2 {
    std::string route_id;
    bool want_qualify{false};
};

/**
 * Outcome of noting a multi-hop qualification request. qualified stays
 * false on every path. Multi-hop qualification stays false and this note
 * qualifies nothing.
 */
struct SwarmNotNoMultiHopQual2Result {
    std::string code;
    bool qualified{false};
};

/**
 * Note a multi-hop qualification request without qualifying the route.
 * Order, first match wins: an empty route_id is ROUTE. want_qualify is
 * HELD. Otherwise the note is NOTED and err is cleared. qualified stays
 * false on every path. Multi-hop qualification stays false and this note
 * qualifies nothing.
 */
SwarmNotNoMultiHopQual2Result SwarmNoteNotNoMultiHopQual2(const SwarmNotNoMultiHopQual2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMULTIHOPQUAL2_H
