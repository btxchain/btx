// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalpair.h>

#include <cstdint>

namespace modelnet {

SwarmEvalPairResult SwarmNoteEvalPair(const SwarmEvalPair& pair, std::string& err)
{
    SwarmEvalPairResult result;
    result.settled = false;
    if (pair.candidate_id.empty() || pair.evaluator_a.empty() || pair.evaluator_b.empty() ||
        pair.domain_a.empty() || pair.domain_b.empty()) {
        result.code = "EVAL";
        err = "EVAL";
        return result;
    }
    // SAME_EVALUATOR wins even when domains differ, outcomes_agree is
    // true, and want_settle is true. A quorum needs distinct evaluators.
    if (pair.evaluator_a == pair.evaluator_b) {
        result.code = "SAME_EVALUATOR";
        result.settled = false;
        err = "SAME_EVALUATOR";
        return result;
    }
    // SAME_DOMAIN wins even when outcomes_agree and want_settle are
    // true. A quorum needs distinct trust domains.
    if (pair.domain_a == pair.domain_b) {
        result.code = "SAME_DOMAIN";
        result.settled = false;
        err = "SAME_DOMAIN";
        return result;
    }
    // Agreement is not settlement. Disagreement is a split.
    if (!pair.outcomes_agree) {
        result.code = "SPLIT";
        result.settled = false;
        err = "SPLIT";
        return result;
    }
    // want_settle holds the pair. This note does not settle.
    if (pair.want_settle) {
        result.code = "HELD";
        result.settled = false;
        err.clear();
        return result;
    }
    // Distinct evaluators in distinct domains that agree are noted.
    // Nothing is graduated.
    result.code = "NOTED";
    result.settled = false;
    err.clear();
    return result;
}

} // namespace modelnet
