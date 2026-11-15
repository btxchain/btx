// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ROUTECHECK_H
#define BTX_MODELNET_SWARM_ROUTECHECK_H

#include <string>

namespace modelnet {

/**
 * A request to classify a payment path. hops is the caller-supplied hop
 * count. preimage_len is the byte length of a hashlock preimage. The three
 * flags are caller claims. This request does not carry a transaction and
 * does not broadcast.
 */
struct SwarmRouteRequest {
    int hops{0};
    int preimage_len{0};
    bool cltv_staggered{false};
    bool lifetime_ok{false};
    bool liquidity_reserved{false};
};

/**
 * A classification answer. qualified and secp_penalty stay false: a direct
 * hashlock is not a routed network, and a complete caller flag set is still
 * not script-enforceable multi-hop. This function does not broadcast and
 * does not apply a secp penalty.
 */
struct SwarmRouteResult {
    bool qualified{false};
    bool secp_penalty{false};
    std::string code;
};

/**
 * Classifies a route request. qualified and secp_penalty stay false in
 * every case. Nothing is broadcast.
 *
 * Order: hops < 1 is ROUTE. preimage_len other than 32 is PREIMAGE. hops
 * == 1 with a 32-byte preimage, lifetime_ok, and liquidity_reserved is
 * DIRECT. That is a direct hashlock, not a routed network, and qualified
 * stays false. cltv_staggered is not required for DIRECT. hops > 1 without
 * cltv_staggered is STAGGER. hops > 1 without lifetime_ok is LIFETIME.
 * hops > 1 without liquidity_reserved is LIQUIDITY. Otherwise hops > 1 is
 * UNQUALIFIED: a complete caller flag set is still not script-enforceable
 * multi-hop. A one-hop request that missed DIRECT because lifetime_ok is
 * false is LIFETIME. A one-hop request that missed DIRECT because
 * liquidity_reserved is false is LIQUIDITY.
 *
 * DIRECT and UNQUALIFIED clear err. Every other code assigns err to that
 * code.
 */
SwarmRouteResult SwarmCheckRoute(const SwarmRouteRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ROUTECHECK_H
