// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTROUTE_H
#define BTX_MODELNET_SWARM_NOTROUTE_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. want_handle asks this note to handle
 * the route.
 *
 * This note does not handle, broadcast, or multihop the route.
 * handled, broadcast, and multihop stay false on every path.
 */
struct SwarmNotRoute {
    std::string route_id;
    bool want_handle{false};
};

/**
 * Outcome of noting a route. handled, broadcast, and multihop stay
 * false on every path.
 */
struct SwarmNotRouteResult {
    std::string code;
    bool handled{false};
    bool broadcast{false};
    bool multihop{false};
};

/**
 * Note a route without handling it.
 * Order, first match wins: an empty route_id is ROUTE and every result
 * bool stays false. want_handle is UNQUALIFIED; handled, broadcast, and
 * multihop stay false. Otherwise the note is NOTED, every result bool
 * stays false, and err is clear.
 */
SwarmNotRouteResult SwarmNoteNotRoute(const SwarmNotRoute& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTROUTE_H
