// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_selfscore.h>

namespace modelnet {

SwarmSelfScoreResult SwarmNoteSelfScore(const SwarmSelfScore& report, std::string& err)
{
    SwarmSelfScoreResult result;
    result.scored = false;
    if (report.report_id.empty()) {
        result.scored = false;
        result.code = "REPORT";
        err = "REPORT";
        return result;
    }
    // An author does not score their own report.
    if (report.same_author) {
        result.scored = false;
        result.code = "NOT_SCORED";
        err = "NOT_SCORED";
        return result;
    }
    if (report.want_score) {
        result.scored = false;
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.scored = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
