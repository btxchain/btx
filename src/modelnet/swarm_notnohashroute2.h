// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHASHROUTE2_H
#define BTX_MODELNET_SWARM_NOTNOHASHROUTE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one route. hashlock marks a hashlock on the route.
 * want_route asks this note to treat the hashlock as a route.
 *
 * A hashlock is not a route.
 * routed stays false on every path.
 */
struct SwarmNotNoHashRoute2 {
    std::string route_id;
    bool hashlock{false};
    bool want_route{false};
};

/**
 * Outcome of noting a hashlock. routed stays false on every path.
 * A hashlock is not a route.
 */
struct SwarmNotNoHashRoute2Result {
    std::string code;
    bool routed{false};
};

/**
 * Note a hashlock without routing it.
 * Order, first match wins: an empty route_id is ROUTE.
 * hashlock is NOT_ROUTE, even when want_route is false.
 * want_route is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * routed stays false on every path.
 * A hashlock is not a route.
 */
SwarmNotNoHashRoute2Result SwarmNoteNotNoHashRoute2(const SwarmNotNoHashRoute2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHASHROUTE2_H
