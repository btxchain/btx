// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CANARYGATE_H
#define BTX_MODELNET_SWARM_CANARYGATE_H

#include <string>

namespace modelnet {

/**
 * A local note about one canary candidate. A regression does not
 * promote a candidate. This gate does not train or move bytes.
 */
struct SwarmCanaryGate {
    std::string candidate_id;
    bool regression{false};
    bool qualified{false};
    bool want_promote{false};
};

/**
 * Outcome of noting a canary. promoted stays false and parent_kept
 * stays true on every path.
 */
struct SwarmCanaryGateResult {
    std::string code;
    bool promoted{false};
    bool parent_kept{true};
};

/**
 * Note a canary without promoting it.
 * Order, first match wins: an empty candidate_id is CANDIDATE. A
 * regression is REGRESSION, including when want_promote is false.
 * A candidate that is not qualified is UNQUALIFIED. A request that
 * wants promotion is HELD. Otherwise the note is NOTED and err is
 * clear. promoted stays false and parent_kept stays true on every
 * path. A canary regression keeps the parent. This gate does not
 * promote.
 */
SwarmCanaryGateResult SwarmGateCanary(const SwarmCanaryGate& gate, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CANARYGATE_H
