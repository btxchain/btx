// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreportrec2.h>

namespace modelnet {

SwarmNotNoReportRec2Result SwarmNoteNotNoReportRec2(const SwarmNotNoReportRec2& note, std::string& err)
{
    // A regression report has not been recorded and this note records nothing.
    SwarmNotNoReportRec2Result result;
    result.recorded = false;
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.recorded = false;
        err = "REPORT";
        return result;
    }
    if (note.want_record) {
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
