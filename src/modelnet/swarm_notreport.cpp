// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notreport.h>

#include <string>

namespace modelnet {

SwarmNotReportResult SwarmNoteNotReport(const SwarmNotReport& note, std::string& err)
{
    SwarmNotReportResult result;
    result.attached = false;
    result.graduated = false;
    // This note does not attach an evaluation report or graduate a model.
    if (note.eval_id.empty()) {
        result.code = "EVAL";
        result.attached = false;
        result.graduated = false;
        err = "EVAL";
        return result;
    }
    if (note.want_attach) {
        result.code = "NOT_ATTACHED";
        result.attached = false;
        result.graduated = false;
        err = "NOT_ATTACHED";
        return result;
    }
    result.code = "NOTED";
    result.attached = false;
    result.graduated = false;
    err.clear();
    return result;
}

} // namespace modelnet
