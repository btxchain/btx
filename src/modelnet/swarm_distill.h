// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DISTILL_H
#define BTX_MODELNET_SWARM_DISTILL_H

#include <string>

namespace modelnet {

/**
 * A request to classify one model operation. op is exactly "merge" or
 * "distill". This request does not carry weights and does not update them.
 */
struct SwarmModelOpRequest {
    std::string op;
    bool evidence_present{false};
    bool evaluated{false};
};

/**
 * A classification answer. performed and averaged stay false: a recorded
 * operation is not an executed weight update. This function does not
 * average weights.
 */
struct SwarmModelOpResult {
    bool performed{false};
    bool averaged{false};
    std::string code;
};

/**
 * Classifies a merge or distill request. performed and averaged stay false
 * in every case. A recorded operation is not an executed weight update.
 * This function does not average weights.
 *
 * Order: an empty op, or an op that is not exactly merge or distill, is
 * MODEL_OP. Missing evidence is EVIDENCE. An unevaluated request is
 * UNEVALUATED. merge is MERGE_RECORDED. distill is DISTILL_RECORDED. On
 * those two recorded codes err is cleared. Otherwise err is the code.
 */
SwarmModelOpResult SwarmClassifyModelOp(const SwarmModelOpRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DISTILL_H
