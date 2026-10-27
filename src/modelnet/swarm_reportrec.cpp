// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reportrec.h>

namespace modelnet {

SwarmReportRecResult SwarmNoteReportRec(const SwarmReportRec& report, std::string& err)
{
    // A regression report record request is held and records nothing.
    SwarmReportRecResult result;
    result.recorded = false;
    if (report.report_id.empty()) {
        result.code = "REPORT";
        result.recorded = false;
        err = "REPORT";
        return result;
    }
    if (report.want_record) {
        result.code = "HELD";
        result.recorded = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.recorded = false;
    err.clear();
    return result;
}

} // namespace modelnet
