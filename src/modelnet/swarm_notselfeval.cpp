// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notselfeval.h>

namespace modelnet {

SwarmNotSelfEvalResult SwarmNoteNotSelfEval(const SwarmNotSelfEval& note, std::string& err)
{
    SwarmNotSelfEvalResult result;
    result.accepted = false;
    result.signed_report = false;
    // An author cannot evaluate self or sign their own report.
    if (note.author_id.empty() || note.evaluator_id.empty()) {
        result.code = "AUTHOR";
        result.accepted = false;
        result.signed_report = false;
        err = "AUTHOR";
        return result;
    }
    if (note.author_id == note.evaluator_id) {
        result.code = "SAME_EVALUATOR";
        result.accepted = false;
        result.signed_report = false;
        err = "SAME_EVALUATOR";
        return result;
    }
    if (note.want_accept) {
        result.code = "NOT_ACCEPTED";
        result.accepted = false;
        result.signed_report = false;
        err = "NOT_ACCEPTED";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.signed_report = false;
    err.clear();
    return result;
}

} // namespace modelnet
