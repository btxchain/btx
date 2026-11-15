// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdistinct.h>

#include <string>

namespace modelnet {

SwarmNotDistinctResult SwarmNoteNotDistinct(const SwarmNotDistinct& note, std::string& err)
{
    SwarmNotDistinctResult result;
    result.signed_report = false;
    result.accepted = false;
    // An author does not sign their own report. This note signs nothing.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.signed_report = false;
        result.accepted = false;
        err = "REPORT";
        return result;
    }
    if (note.same_author) {
        result.code = "SAME_EVALUATOR";
        result.signed_report = false;
        result.accepted = false;
        err = "SAME_EVALUATOR";
        return result;
    }
    if (note.want_sign) {
        result.code = "NOT_ACCEPTED";
        result.signed_report = false;
        result.accepted = false;
        err = "NOT_ACCEPTED";
        return result;
    }
    result.code = "NOTED";
    result.signed_report = false;
    result.accepted = false;
    err.clear();
    return result;
}

} // namespace modelnet
