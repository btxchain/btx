// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoauthor.h>

#include <string>

namespace modelnet {

SwarmNotNoAuthorResult SwarmNoteNotNoAuthor(const SwarmNotNoAuthor& note, std::string& err)
{
    SwarmNotNoAuthorResult result;
    result.signed_report = false;
    result.accepted = false;
    // An author does not sign their own report.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.signed_report = false;
        result.accepted = false;
        err = "REPORT";
        return result;
    }
    // A self-signed report is SAME_EVALUATOR even when want_sign is false.
    if (note.self_signed) {
        result.code = "SAME_EVALUATOR";
        result.signed_report = false;
        result.accepted = false;
        err = "SAME_EVALUATOR";
        return result;
    }
    // This note signs nothing. An author does not sign their own report.
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
