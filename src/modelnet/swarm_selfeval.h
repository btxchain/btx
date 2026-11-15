// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SELFEVAL_H
#define BTX_MODELNET_SWARM_SELFEVAL_H

#include <string>

namespace modelnet {

/**
 * A note that an author asked an evaluator to score a model.
 * want_score records that the caller asked this note to score.
 *
 * An author cannot evaluate self. This note does not score a model.
 * No hostnames or IPs are used.
 */
struct SwarmSelfEval {
    std::string author_id;
    std::string evaluator_id;
    bool want_score{false};
};

/**
 * Outcome of noting a self-evaluation request. scored stays false on
 * every path: this note does not score a model.
 */
struct SwarmSelfEvalResult {
    bool scored{false};
    std::string code;
};

/**
 * Note a self-evaluation request without scoring a model.
 * Order, first match wins: an empty author_id or evaluator_id is
 * AUTHOR. author_id equal to evaluator_id is SELF, including when
 * want_score is true. want_score is HELD and err is cleared.
 * Otherwise the note is NOTED and err is cleared.
 * scored stays false on every path. An author cannot evaluate self.
 * This note does not score a model.
 */
SwarmSelfEvalResult SwarmNoteSelfEval(const SwarmSelfEval& eval, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SELFEVAL_H
