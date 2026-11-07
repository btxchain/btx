// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_frontier.h>
#include <modelnet/swarm_regress.h>

namespace modelnet {

bool SwarmAttachRegression(SwarmRegressionReport& report, std::string& err)
{
    if (report.candidate_id.empty() || report.suite_id.empty()) {
        report.blocks_promotion = false;
        err = "REGRESSION";
        return false;
    }
    if (!SwarmSafetyAllowsGraduation(report.safety_regression, report.broad_regression)) {
        report.blocks_promotion = true;
        err = "REGRESSION";
        return false;
    }
    report.blocks_promotion = false;
    err.clear();
    return true;
}

} // namespace modelnet
