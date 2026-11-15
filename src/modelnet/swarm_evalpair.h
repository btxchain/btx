// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_EVALPAIR_H
#define BTX_MODELNET_SWARM_EVALPAIR_H

#include <string>

namespace modelnet {

/**
 * Two evaluator notes on one candidate across trust domains.
 * candidate_id names the candidate. evaluator_a and domain_a are the
 * first note. evaluator_b and domain_b are the second note.
 * outcomes_agree is whether the two notes agree. want_settle asks this
 * note to settle.
 *
 * A quorum needs distinct evaluators and distinct trust domains.
 * Agreement is not settlement. This note does not graduate a candidate.
 * settled stays false on every path. Nothing is graduated. No hostnames
 * or IPs are used.
 */
struct SwarmEvalPair {
    std::string candidate_id;
    std::string evaluator_a;
    std::string evaluator_b;
    std::string domain_a;
    std::string domain_b;
    bool outcomes_agree{false};
    bool want_settle{false};
};

/**
 * Outcome of noting an evaluator pair. settled stays false on every
 * path: agreement is not settlement, and this note does not graduate a
 * candidate. Nothing is graduated.
 */
struct SwarmEvalPairResult {
    bool settled{false};
    std::string code;
};

/**
 * Note an evaluator pair without settling or graduating a candidate.
 * A quorum needs distinct evaluators and distinct trust domains.
 * Agreement is not settlement.
 * Order, first match wins: an empty candidate_id, evaluator_a,
 * evaluator_b, domain_a, or domain_b is EVAL. The same evaluator on
 * both notes is SAME_EVALUATOR. This wins even when domains differ,
 * outcomes_agree is true, and want_settle is true. The same trust
 * domain on both notes is SAME_DOMAIN. This wins even when
 * outcomes_agree and want_settle are true. Disagreement is SPLIT.
 * want_settle is HELD and err is cleared. Otherwise the pair is NOTED
 * and err is cleared.
 * settled stays false on every path. Nothing is graduated. No hostnames
 * or IPs are used.
 */
SwarmEvalPairResult SwarmNoteEvalPair(const SwarmEvalPair& pair, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_EVALPAIR_H
