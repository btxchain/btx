// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag08.h>

namespace modelnet {

SwarmFlag08Result SwarmStageEvaluate(const SwarmFlag08& in, std::string& err)
{
    SwarmFlag08Result result;
    result.scored = false;
    result.retained = false;
    result.rejected = false;
    result.graduated = false;
    result.passed = false;
    if (in.candidate_id.empty() || in.evaluator_id.empty() || in.author_id.empty()) {
        result.code = "CANDIDATE";
        result.scored = false;
        result.retained = false;
        result.rejected = false;
        result.graduated = false;
        result.passed = false;
        err = "CANDIDATE";
        return result;
    }
    // Independent evaluators. The author is not the evaluator.
    if (in.evaluator_id == in.author_id) {
        result.code = "SAME_EVALUATOR";
        result.scored = false;
        result.graduated = false;
        result.passed = false;
        err = "SAME_EVALUATOR";
        return result;
    }
    // Tasks stay withheld.
    if (!in.withheld) {
        result.code = "NOT_WITHHELD";
        result.scored = false;
        result.graduated = false;
        result.passed = false;
        err = "NOT_WITHHELD";
        return result;
    }
    // A failure is kept and the candidate is not graduated.
    if (in.failed) {
        result.code = "RETAINED";
        result.retained = true;
        result.rejected = true;
        result.scored = false;
        result.graduated = false;
        result.passed = false;
        err.clear();
        return result;
    }
    if (in.want_score) {
        result.code = "NOT_SCORED";
        result.scored = false;
        result.graduated = false;
        result.passed = false;
        err = "NOT_SCORED";
        return result;
    }
    // An unqualified candidate is not passed.
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.scored = false;
        result.graduated = false;
        result.passed = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.scored = false;
    result.retained = false;
    result.rejected = false;
    result.graduated = false;
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
