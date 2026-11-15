// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_HOPS_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_HOPS_H

#include <modelnet/swarm_routebook/types.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Empty route or empty hop is ROUTE.
 * A present name pair leaves err unchanged.
 */
bool SwarmRouteBookNamesPresent(const std::string& route, const std::string& hop, std::string& err);

/** Hop count of a path, saturated at int64 max. */
int64_t SwarmRouteBookHopCountOf(const SwarmRouteBookPath& path);

/**
 * The stored hop with this name, or nullptr when the path has no such hop.
 * The pointer addresses an element of path.hops.
 */
const SwarmRouteBookHopRecord* SwarmRouteBookFindHop(const SwarmRouteBookPath& path, const std::string& hop);

/**
 * Append one hop onto a path.
 * An empty hop is ROUTE and the path stays unchanged.
 * A hop already on the path is REPLAY and the first expiry stays, including
 * when cltv_expiry is below 0.
 * cltv_expiry below 0 on a new hop is EXPIRY and the path stays unchanged.
 * Otherwise the hop is appended and err is cleared.
 * This does not write delta_bound, bound_delta, or outputs_covered.
 */
bool SwarmRouteBookAppendHop(SwarmRouteBookPath& path, const std::string& hop, int64_t cltv_expiry, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_HOPS_H
