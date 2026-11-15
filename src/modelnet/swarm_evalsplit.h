// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_EVALSPLIT_H
#define BTX_MODELNET_SWARM_EVALSPLIT_H

#include <string>

namespace modelnet {

/**
 * Two evaluator notes on one candidate. candidate_id names the candidate.
 * evaluator_id and outcome are the first note. other_evaluator_id and
 * other_outcome are the second note.
 *
 * This is a local comparison of two notes. It does not graduate a
 * candidate. No hostnames or IPs are used.
 */
struct SwarmEvalSplit {
    std::string candidate_id;
    std::string evaluator_id;
    std::string outcome;
    std::string other_evaluator_id;
    std::string other_outcome;
};

/**
 * Outcome of comparing two evaluator notes. settled stays false on every
 * path: two notes, even when they agree, are not a quorum and do not
 * graduate a candidate.
 */
struct SwarmEvalSplitResult {
    bool settled{false};
    std::string code;
};

/**
 * Compare two evaluator notes without graduating a candidate.
 * Order, first match wins: any empty field is EVAL. The same evaluator
 * on both notes is SAME_EVALUATOR. Differing outcomes are SPLIT.
 * Otherwise the notes are AGREED and err is clear.
 * settled stays false on every path. Two notes, even when they agree,
 * are not a quorum and do not graduate a candidate. No hostnames or IPs
 * are used.
 */
SwarmEvalSplitResult SwarmNoteEvalSplit(const SwarmEvalSplit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_EVALSPLIT_H
