// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalsplit.h>

namespace modelnet {

SwarmEvalSplitResult SwarmNoteEvalSplit(const SwarmEvalSplit& note, std::string& err)
{
    SwarmEvalSplitResult result;
    result.settled = false;
    if (note.candidate_id.empty() || note.evaluator_id.empty() || note.outcome.empty() ||
        note.other_evaluator_id.empty() || note.other_outcome.empty()) {
        result.code = "EVAL";
        err = "EVAL";
        return result;
    }
    if (note.evaluator_id == note.other_evaluator_id) {
        result.code = "SAME_EVALUATOR";
        err = "SAME_EVALUATOR";
        return result;
    }
    if (note.outcome != note.other_outcome) {
        result.code = "SPLIT";
        err = "SPLIT";
        return result;
    }
    result.code = "AGREED";
    result.settled = false;
    err.clear();
    return result;
}

} // namespace modelnet
