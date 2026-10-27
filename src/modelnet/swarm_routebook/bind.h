// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_BIND_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_BIND_H

#include <modelnet/swarm_routebook/types.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Store upstream_delta when it meets hop_count * kSwarmRouteBookMargin.
 * A shortfall is SLACK and leaves delta_bound and bound_delta unchanged.
 * A stored delta does not qualify the route. No atoms are moved.
 */
bool SwarmRouteBookApplyBind(SwarmRouteBookPath& path, int64_t upstream_delta, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_BIND_H
