// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_selfeval.h>

namespace modelnet {

SwarmSelfEvalResult SwarmNoteSelfEval(const SwarmSelfEval& eval, std::string& err)
{
    SwarmSelfEvalResult result;
    result.scored = false;
    if (eval.author_id.empty() || eval.evaluator_id.empty()) {
        result.code = "AUTHOR";
        err = "AUTHOR";
        return result;
    }
    // An author cannot evaluate self. SELF wins even when want_score is true.
    if (eval.author_id == eval.evaluator_id) {
        result.code = "SELF";
        err = "SELF";
        return result;
    }
    if (eval.want_score) {
        result.code = "HELD";
        result.scored = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.scored = false;
    err.clear();
    return result;
}

} // namespace modelnet
