// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LEARNERQ_H
#define BTX_MODELNET_SWARM_LEARNERQ_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Caller description of one learner-queue item bound to a policy version.
 * queue_id names the queue, policy_id names the policy version, and
 * item_id names the item. credential, private_data, and want_run are
 * caller claims.
 *
 * A learner queue can remember one item for a policy version and does not
 * run training.
 */
struct SwarmLearnerItem {
    std::string queue_id;
    std::string policy_id;
    std::string item_id;
    bool credential{false};
    bool private_data{false};
    bool want_run{false};
};

/**
 * Outcome of remembering one learner item. running stays false on every
 * path. depth is 0 when the item is refused and 1 when it is remembered.
 */
struct SwarmLearnerResult {
    std::string code;
    bool queued{false};
    bool running{false};
    int64_t depth{0};
};

/**
 * Remember one learner item for a policy version.
 * Order, first match wins: an empty queue_id is QUEUE. An empty policy_id
 * is POLICY. credential true is CREDENTIAL, even when want_run is false.
 * private_data true is PRIVATE. An empty item_id is ITEM. want_run true is
 * HELD with queued true and depth 1. Otherwise the code is NOTED, err is
 * cleared, queued is true, and depth is 1.
 * running stays false on every path.
 * A learner queue can remember one item for a policy version and does not
 * run training.
 */
SwarmLearnerResult SwarmEnqueueLearner(const SwarmLearnerItem& item, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LEARNERQ_H
