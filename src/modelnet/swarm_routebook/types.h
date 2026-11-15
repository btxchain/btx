// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_TYPES_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One stored hop margin. hop is the hop name on a route.
 * cltv_expiry is the first accepted expiry. A later add of the same hop
 * leaves this expiry in place.
 */
struct SwarmRouteBookHopRecord {
    std::string hop;
    int64_t cltv_expiry{0};
};

/**
 * Hop margins for one route id.
 * hops grows only when AddHop accepts a new hop.
 * delta_bound is true only after Bind stores upstream_delta.
 * outputs_covered is true only after Sighash stores a description that
 * covered outputs. The record has no signing key, no channel, and no
 * atom counter. qualified is not a field on this record.
 */
struct SwarmRouteBookPath {
    std::vector<SwarmRouteBookHopRecord> hops;
    bool delta_bound{false};
    int64_t bound_delta{0};
    bool outputs_covered{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_TYPES_H
