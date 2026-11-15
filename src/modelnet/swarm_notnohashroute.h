// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHASHROUTE_H
#define BTX_MODELNET_SWARM_NOTNOHASHROUTE_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. hashlock marks a hashlock on the route.
 * want_qualify asks this note to qualify the route.
 *
 * A hashlock is not a qualified routed network.
 * qualified and multihop stay false on every path.
 */
struct SwarmNotNoHashRoute {
    std::string route_id;
    bool hashlock{false};
    bool want_qualify{false};
};

/**
 * Outcome of noting a hashlock route. qualified and multihop stay false
 * on every path. A hashlock is not a qualified routed network.
 */
struct SwarmNotNoHashRouteResult {
    std::string code;
    bool qualified{false};
    bool multihop{false};
};

/**
 * Note a hashlock route without qualifying it.
 * Order, first match wins: an empty route_id is ROUTE.
 * hashlock is UNQUALIFIED, even when want_qualify is false.
 * want_qualify is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * qualified and multihop stay false on every path.
 * A hashlock is not a qualified routed network.
 */
SwarmNotNoHashRouteResult SwarmNoteNotNoHashRoute(const SwarmNotNoHashRoute& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHASHROUTE_H
