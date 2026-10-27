// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_distill.h>

namespace modelnet {
namespace {

SwarmModelOpResult Finish(const std::string& code, std::string& err, bool recorded)
{
    SwarmModelOpResult result;
    result.performed = false;
    result.averaged = false;
    result.code = code;
    if (recorded) {
        err.clear();
    } else {
        err = code;
    }
    return result;
}

} // namespace

SwarmModelOpResult SwarmClassifyModelOp(const SwarmModelOpRequest& request, std::string& err)
{
    if (request.op.empty() || (request.op != "merge" && request.op != "distill")) {
        return Finish("MODEL_OP", err, false);
    }
    if (!request.evidence_present) {
        return Finish("EVIDENCE", err, false);
    }
    if (!request.evaluated) {
        return Finish("UNEVALUATED", err, false);
    }
    if (request.op == "merge") {
        return Finish("MERGE_RECORDED", err, true);
    }
    return Finish("DISTILL_RECORDED", err, true);
}

} // namespace modelnet
