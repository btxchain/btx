// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoeval.h>

#include <string>

namespace modelnet {

SwarmNotNoEvalResult SwarmNoteNotNoEval(const SwarmNotNoEval& note, std::string& err)
{
    SwarmNotNoEvalResult result;
    result.accepted = false;
    result.signed_report = false;
    // An author does not evaluate their own report.
    if (note.author_id.empty() || note.evaluator_id.empty()) {
        result.code = "AUTHOR";
        result.accepted = false;
        result.signed_report = false;
        err = "AUTHOR";
        return result;
    }
    // The same author and evaluator is SAME_EVALUATOR even when want_accept is false.
    if (note.author_id == note.evaluator_id) {
        result.code = "SAME_EVALUATOR";
        result.accepted = false;
        result.signed_report = false;
        err = "SAME_EVALUATOR";
        return result;
    }
    // This note accepts nothing. An author does not evaluate their own report.
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
