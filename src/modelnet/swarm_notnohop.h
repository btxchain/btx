// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOP_H
#define BTX_MODELNET_SWARM_NOTNOHOP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one route. hops is a caller-supplied hop count.
 * want_qualify asks this note to qualify the route.
 *
 * More than one hop is not a qualified route.
 * qualified and multihop stay false on every path.
 */
struct SwarmNotNoHop {
    std::string route_id;
    int64_t hops{0};
    bool want_qualify{false};
};

/**
 * Outcome of noting a hop qualification request. qualified and multihop
 * stay false on every path. More than one hop is not a qualified route.
 */
struct SwarmNotNoHopResult {
    std::string code;
    bool qualified{false};
    bool multihop{false};
};

/**
 * Note a hop qualification request without qualifying the route.
 * Order, first match wins: an empty route_id is ROUTE.
 * hops greater than 1 is UNQUALIFIED, even when want_qualify is false.
 * want_qualify is UNQUALIFIED.
 * Otherwise the note is NOTED and err is clear.
 * qualified and multihop stay false on every path.
 * More than one hop is not a qualified route.
 */
SwarmNotNoHopResult SwarmNoteNotNoHop(const SwarmNotNoHop& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOP_H
