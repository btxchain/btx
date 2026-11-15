// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG08_H
#define BTX_MODELNET_SWARM_FLAG08_H

#include <string>

namespace modelnet {

/**
 * A local note about flagship stage 8 evaluate: independent evaluators
 * and withheld tasks. candidate_id names the candidate. evaluator_id
 * names the evaluator. author_id names the author. withheld asks this
 * note to treat the tasks as withheld. failed asks this note to retain
 * a failure. want_score asks this note to score the candidate.
 * want_pass asks this note to treat the candidate as passed.
 *
 * scored, passed, and graduated stay false on every path. A failure is
 * kept and the candidate is not graduated. An unqualified candidate is
 * not passed.
 */
struct SwarmFlag08 {
    std::string candidate_id;
    std::string evaluator_id;
    std::string author_id;
    bool withheld{false};
    bool failed{false};
    bool want_score{false};
    bool want_pass{false};
};

/**
 * Outcome of noting flagship stage 8 evaluate. scored, passed, and
 * graduated stay false: this note does not score, pass, or graduate a
 * candidate.
 */
struct SwarmFlag08Result {
    std::string code;
    bool scored{false};
    bool retained{false};
    bool rejected{false};
    bool graduated{false};
    bool passed{false};
};

/**
 * Note flagship stage 8 evaluate. Independent evaluators and withheld
 * tasks. Order, first match wins: an empty candidate_id, evaluator_id,
 * or author_id is CANDIDATE and every result bool stays false.
 * evaluator_id equal to author_id is SAME_EVALUATOR. withheld false is
 * NOT_WITHHELD. failed is RETAINED: the failure is kept, the candidate
 * is rejected, and err is cleared. want_score is NOT_SCORED. want_pass
 * is UNQUALIFIED. Otherwise the note is NOTED and err is cleared.
 * scored, passed, and graduated stay false on every path. A failure is
 * kept and the candidate is not graduated.
 */
SwarmFlag08Result SwarmStageEvaluate(const SwarmFlag08& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG08_H
