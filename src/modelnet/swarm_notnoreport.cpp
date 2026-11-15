// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreport.h>

#include <string>

namespace modelnet {

SwarmNotNoReportResult SwarmNoteNotNoReport(const SwarmNotNoReport& note, std::string& err)
{
    SwarmNotNoReportResult result;
    result.accepted = false;
    result.signed_report = false;
    // An author does not accept their own report.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.accepted = false;
        result.signed_report = false;
        err = "REPORT";
        return result;
    }
    if (note.same_author) {
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
