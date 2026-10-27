// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMULTIHOP_H
#define BTX_MODELNET_SWARM_NOTMULTIHOP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one route. hops is a caller-supplied hop count.
 * want_qualify asks this note to qualify the route as a routed network.
 *
 * A hashlock is not a qualified routed network.
 * qualified stays false on every path. multihop stays false on every path.
 */
struct SwarmNotMultiHop {
    std::string route_id;
    int64_t hops{0};
    bool want_qualify{false};
};

/**
 * Outcome of noting a multi-hop qualification request. qualified and multihop
 * stay false on every path: a hashlock is not a qualified routed network.
 */
struct SwarmNotMultiHopResult {
    std::string code;
    bool qualified{false};
    bool multihop{false};
};

/**
 * Note a multi-hop qualification request without qualifying the route.
 * Order, first match wins: an empty route_id or hops < 1 is ROUTE.
 * hops > 1 is UNQUALIFIED, even when want_qualify is true.
 * want_qualify is HELD and err is clear.
 * Otherwise the note is NOTED and err is clear.
 * qualified and multihop stay false on every path.
 * A hashlock is not a qualified routed network.
 */
SwarmNotMultiHopResult SwarmNoteNotMultiHop(const SwarmNotMultiHop& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMULTIHOP_H
