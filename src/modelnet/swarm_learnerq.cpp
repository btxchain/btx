// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_learnerq.h>

#include <string>

namespace modelnet {

SwarmLearnerResult SwarmEnqueueLearner(const SwarmLearnerItem& item, std::string& err)
{
    // A learner queue can remember one item for a policy version and does not run training.
    SwarmLearnerResult result;
    result.running = false;
    if (item.queue_id.empty()) {
        result.code = "QUEUE";
        result.queued = false;
        result.running = false;
        result.depth = 0;
        err = "QUEUE";
        return result;
    }
    if (item.policy_id.empty()) {
        result.code = "POLICY";
        result.queued = false;
        result.running = false;
        result.depth = 0;
        err = "POLICY";
        return result;
    }
    if (item.credential) {
        result.code = "CREDENTIAL";
        result.queued = false;
        result.running = false;
        result.depth = 0;
        err = "CREDENTIAL";
        return result;
    }
    if (item.private_data) {
        result.code = "PRIVATE";
        result.queued = false;
        result.running = false;
        result.depth = 0;
        err = "PRIVATE";
        return result;
    }
    if (item.item_id.empty()) {
        result.code = "ITEM";
        result.queued = false;
        result.running = false;
        result.depth = 0;
        err = "ITEM";
        return result;
    }
    if (item.want_run) {
        result.code = "HELD";
        result.queued = true;
        result.running = false;
        result.depth = 1;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.queued = true;
    result.running = false;
    result.depth = 1;
    err.clear();
    return result;
}

} // namespace modelnet
