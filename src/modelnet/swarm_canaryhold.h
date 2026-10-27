// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CANARYHOLD_H
#define BTX_MODELNET_SWARM_CANARYHOLD_H

#include <string>

namespace modelnet {

/**
 * A local note about one canary candidate. Activation and graduation
 * are not provided.
 */
struct SwarmCanaryHoldRequest {
    std::string candidate_id;
    bool canary_started{false};
    bool regression{false};
    bool want_activate{false};
};

/**
 * A local canary note. activated stays false: a note does not activate
 * a candidate and does not graduate it.
 */
struct SwarmCanaryHoldResult {
    bool activated{false};
    std::string code;
};

/**
 * Order, first match wins: an empty candidate_id is CANARY. A canary
 * that has not started is NOT_STARTED, including when regression or
 * want_activate is also true. A regression is REGRESSION, including
 * when want_activate is also true. A request that wants activation is
 * HELD and err is clear. Otherwise the note is NOTED and err is clear.
 * activated stays false on every path. This records a local note. It
 * does not activate a candidate and does not graduate it.
 */
SwarmCanaryHoldResult SwarmHoldCanary(const SwarmCanaryHoldRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CANARYHOLD_H
