// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_SLACK_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_SLACK_H

#include <modelnet/swarm_routebook/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Required slack is hop_count * kSwarmRouteBookMargin.
 * Zero hops require 0. Two hops require 320. Three hops require 480.
 * A negative hop count fails and sets slack to 0.
 * A product that does not fit in int64 fails and sets slack to int64 max.
 */
bool SwarmRouteBookRequiredSlack(int64_t hop_count, int64_t& slack);

/**
 * upstream_delta meets slack when it is greater than or equal to the
 * required slack. A shortfall, a negative hop count, or an overflowing
 * product is SLACK. On success required is the slack and err is cleared.
 * Meeting slack does not qualify a route.
 */
bool SwarmRouteBookDeltaMeetsSlack(int64_t hop_count, int64_t upstream_delta, int64_t& required, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_SLACK_H
